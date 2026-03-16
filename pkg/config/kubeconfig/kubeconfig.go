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

package kubeconfig

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config/certs"
)

type KubeconfigParams struct {
	ServerURL                  string
	CertificateAuthorityBase64 string
	Token                      string
}

// CreateWebhookKubeconfig will create a kubeconfig for the webhook server
func CreateWebhookKubeconfig(cert *tls.Certificate, kubeconfigPath, serverURL string) error {
	logrus.WithField("kubeconfigPath", kubeconfigPath).Info("writing webhook kubeconfig file")

	return KubeconfigParams{
		ServerURL:                  serverURL,
		CertificateAuthorityBase64: certs.CertToPEMBase64(cert.Certificate[0]),
	}.WriteKubeconfig(kubeconfigPath)
}

func (p KubeconfigParams) WriteKubeconfig(outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			logrus.WithError(err).Warn("error closing file")
		}
	}()

	_, err = fmt.Fprintf(f, `
clusters:
  - name: aws-iam-authenticator
    cluster:
      certificate-authority-data: %s
      server: %s
# user refers to the API server client
users:
  - name: apiserver
current-context: webhook
contexts:
- name: webhook
  context:
    cluster: aws-iam-authenticator
    user: apiserver
`, p.CertificateAuthorityBase64, p.ServerURL)
	return err
}
