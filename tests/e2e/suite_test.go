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
	"os"
	"path"
	"path/filepath"
	"testing"

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
	if os.Getenv(kubeconfigEnvVar) == "" {
		defaultKubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		os.Setenv(kubeconfigEnvVar, defaultKubeconfig)
	}
	flag.StringVar(&kubeConfig, "kubeconfig", os.Getenv(kubeconfigEnvVar), "Path to kubeconfig file")
	flag.StringVar(&reportDir, "report-dir", "", "Directory for JUnit XML reports")
	flag.StringVar(&reportPrefix, "report-prefix", "", "Prefix for JUnit report filenames")
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	GinkgoWriter.Printf("Starting e2e run %q on Ginkgo node %d\n", uuid.NewUUID(), GinkgoParallelProcess())
	RunSpecs(t, "AWS IAM Authenticator End-to-End Tests")
}

var _ = ReportAfterSuite("junit reporter", func(report Report) {
	if reportDir == "" {
		return
	}
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		GinkgoWriter.Printf("Failed creating report directory: %v\n", err)
		return
	}
	reporters.GenerateJUnitReport(report, path.Join(reportDir, fmt.Sprintf("junit_%v%02d.xml", reportPrefix, GinkgoParallelProcess())))
})
