package config

import (
	"testing"
)

func TestServerUrl(t *testing.T) {
	tests := []struct {
		config   Config
		expected string
	}{
		{
			config: Config{
				Hostname: "example.com",
				HostPort: 6443,
			},
			expected: "https://example.com:6443/authenticate",
		},
		{
			config: Config{
				Hostname: "127.0.0.1",
				HostPort: 8080,
			},
			expected: "https://127.0.0.1:8080/authenticate",
		},
		{
			config: Config{
				Hostname: "2001:db8::1:0",
				HostPort: 1234,
			},
			expected: "https://[2001:db8::1:0]:1234/authenticate",
		},
	}

	for _, test := range tests {
		actual := test.config.ServerURL()
		if actual != test.expected {
			t.Errorf("Expected %q, got %q", test.expected, actual)
		}
	}
}
