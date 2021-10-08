package server

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/tests/integration/testutils"
)

func TestServer(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	adminClient, execClient := testutils.StartAuthenticatorTestFramework(
		t, stopCh, testutils.AuthenticatorTestFrameworkSetup{
			ModifyAuthenticatorServerConfig: func(*config.Config) {},
			AuthenticatorClientBinaryPath:   authenticatorBinaryPath,
			TestArtifacts:                   testArtifactsDir,
			ClusterID:                       "test-cluster",
			BackendMode:                     []string{"EKSConfigMap"},
			RoleArn:                         roleARN,
		},
	)

	t.Log("Creating aws-auth")
	userName := "test-user"
	_, err := adminClient.CoreV1().ConfigMaps("kube-system").Create(context.TODO(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-auth"},
		Data:       map[string]string{"mapRoles": fmt.Sprintf("    - rolearn: %s\n      username: %s\n", roleARN, userName)},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating aws-auth configmap: %v\n", err)
	}

	_, err = adminClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-user-binding"},
		Subjects: []rbacv1.Subject{
			{
				Kind: "User",
				Name: userName,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "cluster-admin",
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating clusterrolebinding: %v\n", err)
	}

	t.Log("Testing authentication")
	_, err = execClient.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("error listing pods: %v\n", err)
	}
}
