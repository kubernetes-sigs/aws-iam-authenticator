/*
Copyright 2017 The Kubernetes Authors.

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

package server

import (
	"flag"
	"testing"

	"k8s.io/kubernetes/test/integration/framework"
)

var (
	authenticatorBinaryPath string
	roleARN                 string
	testArtifactsDir        string
)

func TestMain(m *testing.M) {
	flag.StringVar(&authenticatorBinaryPath, "authenticator-binary-path", "/usr/local/bin/aws-iam-authenticator", "Location of the aws-iam-authenticator binary to test with.")
	flag.StringVar(&roleARN, "role-arn", "", "ARN of role to be authenticated in the test. This role ARN is added to the configmap and it should be assumable by the test run.")
	flag.StringVar(&testArtifactsDir, "test-artifacts-dir", "", "Directory used for artifacts generated from test runs.")

	framework.EtcdMain(m.Run)
}
