package testutils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	client "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/endpoints"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
	"sigs.k8s.io/aws-iam-authenticator/pkg/server"
)

// AuthenticatorTestFrameworkSetup holds configuration information for a kube-apiserver test server.
type AuthenticatorTestFrameworkSetup struct {
	ModifyAuthenticatorServerConfig func(*config.Config)
	AuthenticatorClientBinaryPath   string
	TestArtifacts                   string
	ClusterID                       string
	BackendMode                     []string
	RoleArn                         string
}

func StartAuthenticatorTestFramework(t *testing.T, setup AuthenticatorTestFrameworkSetup) (client.Interface, client.Interface, func()) {
	metrics.InitMetrics(prometheus.NewRegistry())

	serverPort := freePort(t)
	healthPort := freePort(t)

	cfg, err := testConfig(t, setup, serverPort, healthPort)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cfg.GetOrCreateX509KeyPair(); err != nil {
		t.Fatal(err)
	}

	if err := cfg.GenerateWebhookKubeconfig(); err != nil {
		t.Fatal(err)
	}

	// Start kube-apiserver and etcd via envtest
	testEnv := &envtest.Environment{
		BinaryAssetsDirectory: envtestBinaryPath(t),
	}
	testEnv.ControlPlane.GetAPIServer().Configure().Set(
		"authentication-token-webhook-config-file",
		cfg.GenerateKubeconfigPath,
	)

	restCfg, err := testEnv.Start()
	if err != nil {
		t.Fatal(err)
	}

	adminClient, err := client.NewForConfig(restCfg)
	if err != nil {
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
		t.Fatal(err)
	}

	// Write a kubeconfig for the authenticator server to connect back to kube-apiserver
	// using client cert auth (envtest provides CertData/KeyData, not BearerToken)
	if err := clientcmd.WriteToFile(clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"kubernetes": {
				Server:                   restCfg.Host,
				CertificateAuthorityData: restCfg.TLSClientConfig.CAData,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"kubernetes": {Cluster: "kubernetes", AuthInfo: "admin"},
		},
		CurrentContext: "kubernetes",
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"admin": {
				ClientCertificateData: restCfg.TLSClientConfig.CertData,
				ClientKeyData:         restCfg.TLSClientConfig.KeyData,
			},
		},
	}, cfg.Kubeconfig); err != nil {
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
		t.Fatal(err)
	}

	stopCh := make(chan struct{})
	httpServer := server.New(context.Background(), cfg)
	go func() {
		httpServer.Run(stopCh)
	}()

	err = wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
		t.Log("Checking authenticator server health...")
		done, err = checkHealth(cfg)
		if err != nil {
			t.Log(err)
			return false, nil
		}
		if !done {
			return false, nil
		}
		t.Log("Authenticator server healthy.")
		return true, nil
	})
	if err != nil {
		close(stopCh)
		httpServer.Close()
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
		t.Fatal(err)
	}

	args := []string{"token", "-i", setup.ClusterID}
	if setup.RoleArn != "" {
		args = append(args, "--role", setup.RoleArn)
	}

	// Build a new rest.Config from the written kubeconfig and add ExecProvider
	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: cfg.Kubeconfig}
	execRestCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		close(stopCh)
		httpServer.Close()
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
		t.Fatal(err)
	}
	execRestCfg.TLSClientConfig.CertData = nil
	execRestCfg.TLSClientConfig.KeyData = nil
	execRestCfg.TLSClientConfig.CertFile = ""
	execRestCfg.TLSClientConfig.KeyFile = ""
	execRestCfg.ExecProvider = &clientcmdapi.ExecConfig{
		Command:         setup.AuthenticatorClientBinaryPath,
		Args:            args,
		APIVersion:      "client.authentication.k8s.io/v1beta1",
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}

	clientWithExecAuthenticator, err := client.NewForConfig(execRestCfg)
	if err != nil {
		close(stopCh)
		httpServer.Close()
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
		t.Fatal(err)
	}

	return adminClient, clientWithExecAuthenticator, func() {
		close(stopCh)
		httpServer.Close()
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Logf("testEnv.Stop: %v", stopErr)
		}
	}
}

func testConfig(t *testing.T, setup AuthenticatorTestFrameworkSetup, serverPort, healthPort int) (config.Config, error) {
	testDir, err := os.MkdirTemp(setup.TestArtifacts, "test-integration-"+t.Name())
	if err != nil {
		return config.Config{}, fmt.Errorf("creating test directory: %w", err)
	}
	t.Logf("Test dir: %v.\n", testDir)

	cfg := config.Config{
		PartitionID:            "aws",
		ClusterID:              setup.ClusterID,
		Hostname:               "localhost",
		HostPort:               serverPort,
		HealthPort:             healthPort,
		KubeconfigPregenerated: true,
		Address:                "127.0.0.1",
		Kubeconfig:             filepath.Join(testDir, "apiserver.kubeconfig"),
		GenerateKubeconfigPath: filepath.Join(testDir, "webhook.kubeconfig"),
		BackendMode:            setup.BackendMode,
		StateDir:               testDir,
	}

	if setup.ModifyAuthenticatorServerConfig != nil {
		setup.ModifyAuthenticatorServerConfig(&cfg)
	}

	// validate any overrides
	if cfg.ClusterID == "" {
		return cfg, errors.New("cluster ID cannot be empty")
	}

	if !slices.Contains(endpoints.PARTITIONS, cfg.PartitionID) {
		return cfg, errors.New("Invalid partition")
	}

	if errs := mapper.ValidateBackendMode(cfg.BackendMode); len(errs) > 0 {
		return cfg, utilerrors.NewAggregate(errs)
	}

	return cfg, nil
}

// envtestBinaryPath resolves the directory containing envtest binaries (kube-apiserver, etcd).
// Checks KUBEBUILDER_ASSETS first, then falls back to setup-envtest, then skips the test.
func envtestBinaryPath(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("KUBEBUILDER_ASSETS"); dir != "" {
		return dir
	}
	// Try setup-envtest from PATH or GOPATH/bin
	candidates := []string{"setup-envtest"}
	if gopath, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		candidates = append(candidates, filepath.Join(strings.TrimSpace(string(gopath)), "bin", "setup-envtest"))
	}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			if out, err := exec.Command(path, "use", "1.35.0", "-p", "path").Output(); err == nil {
				return strings.TrimSpace(string(out))
			}
		}
	}
	t.Skip("KUBEBUILDER_ASSETS not set and setup-envtest not available.\n" +
		"Install: go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest\n" +
		"Then set: export KUBEBUILDER_ASSETS=$(setup-envtest use 1.35.0 -p path)")
	return ""
}

// checkHealth returns true when the authenticator server is healthy
func checkHealth(cfg config.Config) (bool, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/healthz", cfg.Address, cfg.HealthPort))
	if err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}

// freePort asks the OS for an available TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not allocate free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}
