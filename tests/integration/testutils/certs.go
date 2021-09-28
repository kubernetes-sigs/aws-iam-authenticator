/*
Copyright 2021 by the contributors.

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
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

func LoadX509Certificate(certPath string) (*x509.Certificate, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, nil
	}

	certPEMBlock, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"certPath": certPath,
	}).Info("loaded existing certificate")
	return cert, nil
}
