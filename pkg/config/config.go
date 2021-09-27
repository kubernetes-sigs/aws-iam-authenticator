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

package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config/certs"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config/kubeconfig"
)

// ServerURL returns the URL to connect to this server.
func (c *Config) ServerURL() string {
	u := url.URL{
		Scheme: "https",
		Host:   c.ServerAddr(),
		Path:   "/authenticate",
	}
	return u.String()
}

// ServerAddr returns the host and port clients should use for server endpoint.
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Hostname, strconv.Itoa(c.HostPort))
}

// ListenAddr returns the IP address and port mapping to bind with
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Address, strconv.Itoa(c.HostPort))
}

// GenerateFiles will generate the certificate and private key and then create the kubeconfig
func (c *Config) GenerateFiles() error {
	// load or generate a certificate+private key
	_, err := c.GetOrCreateX509KeyPair()
	if err != nil {
		return fmt.Errorf("could not load/generate a certificate")
	}
	err = c.GenerateWebhookKubeconfig()
	if err != nil {
		return fmt.Errorf("could not generate a webhook kubeconfig at %s: %v", c.GenerateKubeconfigPath, err)
	}
	return nil
}

func (c *Config) GenerateWebhookKubeconfig() error {
	cert, err := certs.LoadX509KeyPair(c.CertPath(), c.KeyPath())
	if err != nil {
		return fmt.Errorf("failed to load an existing certificate: %v", err)
	}

	return kubeconfig.CreateWebhookKubeconfig(cert, c.GenerateKubeconfigPath, c.ServerURL())
}

// CertPath returns the path to the pem file containing the certificate
func (c *Config) CertPath() string {
	return filepath.Join(c.StateDir, "cert.pem")
}

// KeyPath returns the path to the pem file containing the private key
func (c *Config) KeyPath() string {
	return filepath.Join(c.StateDir, "key.pem")
}

func (c *Config) CertOpts() certs.CertificateOptions {
	return certs.CertificateOptions{
		CertPath: c.CertPath(),
		KeyPath:  c.KeyPath(),
		Hostname: c.Hostname,
		Address:  c.Address,
		Lifetime: certLifetime,
	}
}

// GetOrCreateCertificate will create a certificate if it cannot find one based on the config
func (c *Config) GetOrCreateX509KeyPair() (*tls.Certificate, error) {
	return certs.GetOrCreateX509KeyPair(c.CertOpts())
}
