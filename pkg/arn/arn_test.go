package arn

import (
	"fmt"
	"testing"
)

type testIAMProvider struct {
	roles map[string]string
}

func (p *testIAMProvider) GetRoleArn(roleName string) (string, error) {
	arn, ok := p.roles[roleName]
	if !ok {
		return "", fmt.Errorf("unknown role")
	}
	return arn, nil
}

func newTestIAMProvider(roles map[string]string) *testIAMProvider {
	return &testIAMProvider{
		roles: roles,
	}
}

var arnTests = []struct {
	arn      string // input arn
	expected string // canonacalized arn
	err      error  // expected error value
}{
	{"NOT AN ARN", "", fmt.Errorf("Not an arn")},
	{"arn:aws:iam::123456789012:user/Alice", "arn:aws:iam::123456789012:user/Alice", nil},
	{"arn:aws:iam::123456789012:role/Users", "arn:aws:iam::123456789012:role/Users", nil},
	{"arn:aws:sts::123456789012:assumed-role/Admin/Session", "arn:aws:iam::123456789012:role/Admin", nil},
	{"arn:aws:sts::123456789012:federated-user/Bob", "arn:aws:sts::123456789012:federated-user/Bob", nil},
	{"arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:root", nil},
	{"arn:aws:sts::123456789012:assumed-role/WithPath/Session", "arn:aws:iam::123456789012:role/Org/Team/WithPath", nil},
	{"arn:aws:sts::123456789012:assumed-role/NotARole/Session", "", fmt.Errorf("unknown role")},
}

func TestUserARN(t *testing.T) {
	iamProvider := newTestIAMProvider(map[string]string{
		"Admin":    "arn:aws:iam::123456789012:role/Admin",
		"WithPath": "arn:aws:iam::123456789012:role/Org/Team/WithPath",
	})
	for _, tc := range arnTests {
		actual, err := Canonicalize(tc.arn, iamProvider)
		if err != nil && tc.err == nil || err == nil && tc.err != nil {
			t.Errorf("Canoncialize(%s) expected err: %v, actual err: %v", tc.arn, tc.err, err)
			continue
		}
		if actual != tc.expected {
			t.Errorf("Canonicalize(%s) expected: %s, actual: %s", tc.arn, tc.expected, actual)
		}
	}
}
