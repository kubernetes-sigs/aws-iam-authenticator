package testutils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	client "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
	"k8s.io/kubernetes/pkg/controlplane"
	"k8s.io/kubernetes/test/integration/framework"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/endpoints"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
	"sigs.k8s.io/aws-iam-authenticator/pkg/server"
)

const (
	hardcodedHealthcheckPort         = 21363
	hardcodedAuthenticatorServerPort = 21362
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

func StartAuthenticatorTestFramework(t *testing.T, setup AuthenticatorTestFrameworkSetup) (client.Interface, client.Interface, framework.TearDownFunc) {
	metrics.InitMetrics(prometheus.NewRegistry())

	cfg, err := testConfig(t, setup)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cfg.GetOrCreateX509KeyPair(); err != nil {
		t.Fatal(err)
	}

	if err := cfg.GenerateWebhookKubeconfig(); err != nil {
		t.Fatal(err)
	}

	adminClient, kubeAPIServerClientConfig, tearDownFn := framework.StartTestServer(context.Background(), t, framework.TestServerSetup{
		ModifyServerRunOptions: func(opts *options.ServerRunOptions) {
			opts.Authentication.WebHook.ConfigFile = cfg.GenerateKubeconfigPath
		},
		ModifyServerConfig: func(config *controlplane.Config) {},
	})

	cert, err := LoadX509Certificate(kubeAPIServerClientConfig.TLSClientConfig.CAFile)
	if err != nil {
		t.Fatal(err)
	}

	// Create API server client kubeconfig, used by the authenticator to update its mapping store when using CRD or EKSConfigMap
	if err := CreateAPIServerClientKubeconfig(cert, kubeAPIServerClientConfig.BearerToken, cfg.Kubeconfig, kubeAPIServerClientConfig.Host); err != nil {
		t.Fatal(err)
	}

	stopCh := make(chan struct{})
	httpServer := server.New(context.TODO(), cfg)
	go func() {
		httpServer.Run(stopCh)
	}()

	err = wait.PollImmediate(100*time.Millisecond, 10*time.Second, func() (done bool, err error) {
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
		t.Fatal(err)
	}

	args := []string{"token", "-i", setup.ClusterID}
	if setup.RoleArn != "" {
		args = append(args, "--role", setup.RoleArn)
	}

	// Create aws-iam-authenticator client
	kubeAPIServerClientConfig.ExecProvider = &clientcmdapi.ExecConfig{
		Command:         setup.AuthenticatorClientBinaryPath,
		Args:            args,
		APIVersion:      "client.authentication.k8s.io/v1beta1",
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}
	kubeAPIServerClientConfig.BearerToken = ""

	clientWithExecAuthenticator, err := client.NewForConfig(kubeAPIServerClientConfig)
	if err != nil {
		t.Fatal(err)
	}

	return adminClient, clientWithExecAuthenticator, func() {
		close(stopCh)
		httpServer.Close()
		tearDownFn()
	}
}

func testConfig(t *testing.T, setup AuthenticatorTestFrameworkSetup) (config.Config, error) {
	testDir, _ := os.MkdirTemp(setup.TestArtifacts, "test-integration-"+t.Name())
	t.Logf("Test dir: %v.\n", testDir)

	cfg := config.Config{
		PartitionID:            "aws",
		ClusterID:              setup.ClusterID,
		Hostname:               "localhost",
		HostPort:               hardcodedAuthenticatorServerPort,
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

// checkHealth returns true when the authenticator server is healthy
func checkHealth(cfg config.Config) (bool, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/healthz", cfg.Address, hardcodedHealthcheckPort))
	if err != nil {
		return false, err
	}

	return resp.StatusCode == http.StatusOK, nil
}
