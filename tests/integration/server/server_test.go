package server

import (
	"context"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/testutils"
)

func TestServer(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	adminClient, execClient := testutils.StartAuthenticatorTestFramework(
		t, stopCh, testutils.AuthenticatorTestFrameworkSetup{
			ModifyAuthenticatorServerConfig: func(*config.Config) {},
			AuthenticatorClientBinaryPath:   authenticatorBinaryPath,
			TestArtifacts:                   testArtifactsDir,
		},
	)

	t.Log("Creating aws-auth")
	_, err := adminClient.CoreV1().ConfigMaps("kube-system").Create(context.TODO(), &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-auth"},
		Data:       map[string]string{"mapRoles": fmt.Sprintf("    - rolearn: %s\n      username: system:node:{{EC2PrivateDNSName}}\n      groups:\n        - system:bootstrappers\n        - system:nodes", roleARN)},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating aws-auth configmap: %v\n", err)
	}

	t.Log("Testing authentication")
	_, err = execClient.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("error listing pods: %v\n", err)
	}
}
