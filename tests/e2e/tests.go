/*
Copyright 2022 The Kubernetes Authors.
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

package e2e

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	restclientset "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	kubeconfigEnv = "KUBECONFIG"
	kubeSystemNs  = "kube-system"
)

var _ = Describe("[iam-auth-e2e] a kubernetes client", func() {
	var (
		cs  clientset.Interface
		cfg *restclientset.Config
	)

	var (
		clusterName      = os.Getenv("CLUSTER_NAME")
		adminRole        = os.Getenv("ADMIN_ROLE")
		usersRole        = os.Getenv("USER_ROLE")
		authenticatorBin = os.Getenv("AUTHENTICATOR_BIN")
	)

	When("authenticaticating directly to the server", func() {
		BeforeEach(func() {
			cfg, _ = clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)
			cs, _ = clientset.NewForConfig(cfg)
		})

		It("successfully sends a request", func() {
			_, err := cs.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	When("assuming the KubernetesAdmin role", func() {
		BeforeEach(func() {
			cfg, _ = clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)

			cfg.TLSClientConfig.CertData = []byte(nil)
			cfg.TLSClientConfig.KeyData = []byte(nil)

			cfg.ExecProvider = &clientcmdapi.ExecConfig{
				Command:         authenticatorBin,
				Args:            []string{"token", "-i", clusterName, "-r", adminRole},
				APIVersion:      "client.authentication.k8s.io/v1beta1",
				InteractiveMode: "Never",
			}

			cs, _ = clientset.NewForConfig(cfg)
		})

		It("should send requests successfully", func() {
			_, err := cs.CoreV1().
				Pods(kubeSystemNs).
				List(context.TODO(), metav1.ListOptions{})

			Expect(err).ToNot(HaveOccurred())
		})

		It("should be authorized to do everything", func() {
			actions := authv1.ResourceAttributes{
				Resource: "*",
				Verb:     "*",
			}

			selfCheck := authv1.SelfSubjectAccessReview{
				Spec: authv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &actions,
				},
			}

			res, err := cs.AuthorizationV1().
				SelfSubjectAccessReviews().
				Create(context.TODO(), &selfCheck, metav1.CreateOptions{})

			Expect(err).ToNot(HaveOccurred())
			Expect(res.Status.Allowed).To(BeTrue())
		})
	})

	When("assuming the KubernetesUsers role", func() {
		BeforeEach(func() {
			cfg, _ = clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)

			cfg.TLSClientConfig.CertData = []byte(nil)
			cfg.TLSClientConfig.KeyData = []byte(nil)

			cfg.ExecProvider = &clientcmdapi.ExecConfig{
				Command:         authenticatorBin,
				Args:            []string{"token", "-i", clusterName, "-r", usersRole},
				APIVersion:      "client.authentication.k8s.io/v1beta1",
				InteractiveMode: "Never",
			}

			cs, _ = clientset.NewForConfig(cfg)
		})

		It("should send a request successfully", func() {
			// pods role gives access to pods

			_, err := cs.CoreV1().
				Pods(kubeSystemNs).
				List(context.TODO(), metav1.ListOptions{})

			Expect(err).ToNot(HaveOccurred())
		})

		It("should be mapped to the right permissions", func() {
			// check that no admin privileges
			actions := authv1.ResourceAttributes{
				Resource: "*",
				Verb:     "*",
			}

			selfCheck := authv1.SelfSubjectAccessReview{
				Spec: authv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &actions,
				},
			}

			res, err := cs.AuthorizationV1().
				SelfSubjectAccessReviews().
				Create(context.TODO(), &selfCheck, metav1.CreateOptions{})

			Expect(err).ToNot(HaveOccurred())
			Expect(res.Status.Allowed).To(BeFalse())

			// check no access to nodes
			_, err = cs.CoreV1().
				Nodes().
				List(context.TODO(), metav1.ListOptions{})

			Expect(err).To(HaveOccurred())
		})
	})

	When("authenticating as a user", func() {
		BeforeEach(func() {
			cfg, _ = clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)

			cfg.TLSClientConfig.CertData = []byte(nil)
			cfg.TLSClientConfig.KeyData = []byte(nil)

			cfg.ExecProvider = &clientcmdapi.ExecConfig{
				Command:         authenticatorBin,
				Args:            []string{"token", "-i", clusterName},
				APIVersion:      "client.authentication.k8s.io/v1beta1",
				InteractiveMode: "Never",
			}

			cs, _ = clientset.NewForConfig(cfg)
		})

		It("should send a request successfully", func() {
			// nodes role gives access to nodes
			_, err := cs.CoreV1().
				Nodes().
				List(context.TODO(), metav1.ListOptions{})

			Expect(err).ToNot(HaveOccurred())
		})

		It("should be mapped to the right permissions", func() {
			// check that no admin privileges
			actions := authv1.ResourceAttributes{
				Resource: "*",
				Verb:     "*",
			}

			selfCheck := authv1.SelfSubjectAccessReview{
				Spec: authv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &actions,
				},
			}

			res, err := cs.AuthorizationV1().
				SelfSubjectAccessReviews().
				Create(context.TODO(), &selfCheck, metav1.CreateOptions{})

			Expect(err).ToNot(HaveOccurred())
			Expect(res.Status.Allowed).To(BeFalse())

			// check no access to pods
			_, err = cs.CoreV1().
				Pods(kubeSystemNs).
				List(context.TODO(), metav1.ListOptions{})

			Expect(err).To(HaveOccurred())
		})
	})
})
