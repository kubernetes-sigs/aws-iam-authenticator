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
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2/reporters"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/uuid"
)

var (
	kubeConfig   string
	reportDir    string
	reportPrefix string
)

const kubeconfigEnvVar = "KUBECONFIG"

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	testing.Init()
	if os.Getenv(kubeconfigEnvVar) == "" {
		defaultKubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		os.Setenv(kubeconfigEnvVar, defaultKubeconfig)
	}
	flag.StringVar(&kubeConfig, "kubeconfig", os.Getenv(kubeconfigEnvVar), "Path to kubeconfig file")
	flag.StringVar(&reportDir, "report-dir", "", "Directory for JUnit XML reports")
	flag.StringVar(&reportPrefix, "report-prefix", "", "Prefix for JUnit report filenames")
	flag.Parse()
}

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)

	// Run tests through the Ginkgo runner with output to console + JUnit for Jenkins
	var r []Reporter
	if reportDir != "" {
		if err := os.MkdirAll(reportDir, 0755); err != nil {
			log.Fatalf("Failed creating report directory: %v", err)
		} else {
			r = append(r, reporters.NewJUnitReporter(path.Join(reportDir, fmt.Sprintf("junit_%v%02d.xml", reportPrefix, GinkgoParallelProcess()))))
		}
	}
	log.Printf("Starting e2e run %q on Ginkgo node %d", uuid.NewUUID(), GinkgoParallelProcess())

	RunSpecsWithDefaultAndCustomReporters(t, "AWS IAM Authenticator End-to-End Tests", r)
}
