/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutils

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/prometheus/client_golang/prometheus"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	client "k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/cmd/kube-apiserver/app/options"
	"k8s.io/kubernetes/pkg/controlplane"
	"k8s.io/kubernetes/test/integration/framework"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
	"sigs.k8s.io/aws-iam-authenticator/pkg/server"
)

const (
	hardcodedHealthcheckPort         = 21363
	hardcodedAuthenticatorServerPort = 21362
	timeout                          = 30 * time.Second
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

	ctx := context.Background()

	adminClient, kubeAPIServerClientConfig, tearDownFn := framework.StartTestServer(ctx, t, framework.TestServerSetup{
		ModifyServerRunOptions: func(opts *options.ServerRunOptions) {
			opts.Authentication.WebHook.ConfigFile = cfg.GenerateKubeconfigPath
			opts.Logs.Verbosity = 9
		},
		ModifyServerConfig: func(config *controlplane.Config) {},
	})

	t.Log("Creating certificates")
	cert, err := LoadX509Certificate(kubeAPIServerClientConfig.TLSClientConfig.CAFile)
	if err != nil {
		t.Fatal(err)
	}

	// Create API server client kubeconfig, used by the authenticator to update its mapping store when using CRD or EKSConfigMap
	if err := CreateAPIServerClientKubeconfig(cert, kubeAPIServerClientConfig.BearerToken, cfg.Kubeconfig, kubeAPIServerClientConfig.Host); err != nil {
		t.Fatal(err)
	}
	t.Log("Running server")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	httpServer := server.New(ctx, cfg)
	go func() {
		httpServer.Run(ctx)
	}()
	t.Log("Ran Authenticator Server.  Sleeping for 5 seconds before checking health...")

	time.Sleep(5 * time.Second)

	err = wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(ctx context.Context) (done bool, err error) {
		t.Log("Checking authenticator server health...")
		done, err = checkHealth(cfg)
		if err != nil {
			t.Log("Error checking authenticator health.", err)
			return false, nil
		}
		if !done {
			return false, nil
		}
		t.Log("Authenticator server healthy.")
		return true, nil
	})
	if err != nil {
		t.Fatal("Error waiting for authenticator to become healthy.", err)
	}

	args := []string{"token", "-i", setup.ClusterID}
	if setup.RoleArn != "" {
		args = append(args, "--role", setup.RoleArn)
	}

	t.Log("Creating exec client")
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
		t.Fatal("Error creating exec client", err)
	}

	return adminClient, clientWithExecAuthenticator, func() {
		t.Log("Cleaning up")
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

	partitionKeys := []string{}
	partitionMap := map[string]endpoints.Partition{}
	for _, p := range endpoints.DefaultPartitions() {
		partitionMap[p.ID()] = p
		partitionKeys = append(partitionKeys, p.ID())
	}
	if _, ok := partitionMap[cfg.PartitionID]; !ok {
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
