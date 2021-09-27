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
	"crypto/x509"
	"text/template"

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config/certs"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config/kubeconfig"
)

// CreateAPIServerClientKubeconfig will create a kubeconfig for the api server client
func CreateAPIServerClientKubeconfig(cert *x509.Certificate, token string, kubeconfigPath, serverURL string) error {
	logrus.WithField("kubeconfigPath", kubeconfigPath).Info("writing api server client kubeconfig file")

	return kubeconfig.KubeconfigParams{
		ServerURL:                  serverURL,
		CertificateAuthorityBase64: certs.CertToPEMBase64(cert.Raw),
		Token:                      token,
	}.WriteKubeconfig(kubeconfigPath, ApiServerClientKubeconfigTemplate)
}

var ApiServerClientKubeconfigTemplate = template.Must(
	template.New("apiserver.kubeconfig").Option("missingkey=error").Parse(`
clusters:
  - name: kubernetes
    cluster:
      certificate-authority-data: {{.CertificateAuthorityBase64}}
      server: {{.ServerURL}}
current-context: kubernetes
contexts:
- name: kubernetes
  context:
    cluster: kubernetes
    user: kubernetes-client
users:
  - name: kubernetes-client
    user:
      token: {{.Token}}
`))
