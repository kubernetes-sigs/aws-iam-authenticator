package config

import (
	"bytes"
	"crypto/x509"
	"net"
	"sort"
	"testing"
)

func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSelfSignCert(t *testing.T) {
	tests := []struct {
		config   Config
		err      error
		dnsNames []string
		ips      []net.IP
	}{
		{
			config: Config{
				Address:  "127.0.0.1",
				Hostname: "127.0.0.1",
			},
			dnsNames: []string{},
			ips:      []net.IP{net.IPv4(127, 0, 0, 1)},
		},
		{
			config: Config{
				Address:  "192.0.2.1",
				Hostname: "example.com",
			},
			dnsNames: []string{"example.com"},
			ips:      []net.IP{net.IPv4(192, 0, 2, 1)},
		},
		{
			config: Config{
				Address:  "::",
				Hostname: "2001:db8::1:0",
			},
			dnsNames: []string{},
			ips:      []net.IP{net.ParseIP("2001:db8::1:0")},
		},
	}

	for _, test := range tests {
		certBytes, keyBytes, err := test.config.selfSignCertificate()
		if err != nil {
			if err != test.err {
				t.Errorf("Expected error %v, got %v", test.err, err)
			}
			continue
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}

		key, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			t.Fatalf("ParsePKCS1PrivateKey: %v", err)
		}
		if err := key.Validate(); err != nil {
			t.Errorf("private key is invalid: %v", err)
		}

		dnsNames := cert.DNSNames
		sort.Strings(dnsNames)
		if !stringsEqual(dnsNames, test.dnsNames) {
			t.Errorf("expected DNSNames %v, got %v", test.dnsNames, dnsNames)
		}

		ips := cert.IPAddresses
		sort.Slice(ips, func(i, j int) bool {
			return bytes.Compare(ips[i].To16(), ips[j].To16()) == -1
		})
		if !ipsEqual(ips, test.ips) {
			t.Errorf("expected IPs %v, got %v", test.ips, ips)
		}
	}
}
