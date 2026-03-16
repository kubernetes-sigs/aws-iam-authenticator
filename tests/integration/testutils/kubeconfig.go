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
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config/certs"
)

// CreateAPIServerClientKubeconfig will create a kubeconfig for the api server client
func CreateAPIServerClientKubeconfig(cert *x509.Certificate, token string, kubeconfigPath, serverURL string) error {
	logrus.WithField("kubeconfigPath", kubeconfigPath).Info("writing api server client kubeconfig file")

	f, err := os.Create(kubeconfigPath)
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
  - name: kubernetes
    cluster:
      certificate-authority-data: %s
      server: %s
current-context: kubernetes
contexts:
- name: kubernetes
  context:
    cluster: kubernetes
    user: kubernetes-client
users:
  - name: kubernetes-client
    user:
      token: %s
`, certs.CertToPEMBase64(cert.Raw), serverURL, token)
	return err
}
