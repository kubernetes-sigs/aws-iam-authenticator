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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"bytes"
	"io/ioutil"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	restclientset "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	restartDelay = 3 * time.Second
	restartWait  = 60 * time.Second
	testTimeout  = 300 * time.Second
)

var _ = Describe("[apiserver] [Disruptive] the apiserver", func() {
	var (
		cs  clientset.Interface
		cfg *restclientset.Config
	)

	When("the manifest changes", func() {
		BeforeEach(func() {
			cfg, _ = clientcmd.BuildConfigFromFlags("", framework.TestContext.KubeConfig)
			cs, _ = clientset.NewForConfig(cfg)

			jobPath := filepath.Join(os.Getenv("BASE_DIR"), "apiserver-restart.yaml")

			b, _ := ioutil.ReadFile(jobPath)
			decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(b), 100)
			jobSpec := &batchv1.Job{}
			_ = decoder.Decode(&jobSpec)

			_, _ = cs.BatchV1().
				Jobs(kubeSystemNs).
				Create(context.TODO(), jobSpec, metav1.CreateOptions{})

			fmt.Printf("Waiting for apiserver to go down...\n")
			err := wait.PollImmediate(restartDelay, restartWait, func() (bool, error) {
				_, pingErr := cs.CoreV1().
					Nodes().
					List(context.TODO(), metav1.ListOptions{})

				if pingErr == nil {
					return false, nil
				} else {
					return true, nil
				}
			})

			if err != nil {
				Fail("Apiserver did not go down! Check if the job was applied correctly?")
			}
		})

		AfterEach(func() {
			cs.BatchV1().Jobs(kubeSystemNs).Delete(context.TODO(), "apiserver-restarter", metav1.DeleteOptions{})
		})

		It("restarts successfully", func() {
			startTime := time.Now()
			err := wait.PollImmediate(1, testTimeout, func() (bool, error) {
				res, pingErr := cs.CoreV1().
					Nodes().
					List(context.TODO(), metav1.ListOptions{})

				if pingErr == nil {
					fmt.Printf("after %ds: apiserver back up: %v nodes\n", int(time.Since(startTime).Seconds()), len(res.Items))
					return true, nil
				} else {
					fmt.Printf("after %ds: %v\n", int(time.Since(startTime).Seconds()), pingErr)
					return false, nil
				}
			})

			Expect(err).ToNot(HaveOccurred())
		})
	})
})
