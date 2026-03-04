package file

import (
	"reflect"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
	"testing"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

func init() {
	config.SSORoleMatchEnabled = true
}

func newConfig() config.Config {
	return config.Config{
		RoleMappings: []config.RoleMapping{
			{
				RoleARN:  "arn:aws:iam::012345678910:role/test-role",
				Username: "shreyas",
				Groups:   []string{"system:masters"},
			},
			{
				SSO: &config.SSOARNMatcher{
					PermissionSetName: "CookieCutterPermissions",
					AccountID:         "012345678910",
				},
				Username: "cookie-cutter",
				Groups:   []string{"system:masters"},
			},
			{
				// test compatibility with eks
				RoleARN:  "arn:aws:sts::012345678910:assumed-role/test-assumed-role/session-name",
				Username: "test",
				Groups:   []string{"system:masters"},
			},
		},
		UserMappings: []config.UserMapping{
			{
				UserARN:  "arn:aws:iam::012345678910:user/donald",
				Username: "donald",
				Groups:   []string{"system:masters"},
			},
		},
		AutoMappedAWSAccounts: []string{"000000000000"},
	}
}

func TestNewFileMapper(t *testing.T) {
	cfg := newConfig()

	expected := &FileMapper{
		roleMap: map[string]config.RoleMapping{
			"arn:aws:iam::012345678910:role/test-role": {
				RoleARN:  "arn:aws:iam::012345678910:role/test-role",
				Username: "shreyas",
				Groups:   []string{"system:masters"},
			},
			"arn:aws:iam::012345678910:role/awsreservedsso_cookiecutterpermissions_*": {
				SSO: &config.SSOARNMatcher{
					PermissionSetName: "CookieCutterPermissions",
					AccountID:         "012345678910",
				},
				Username: "cookie-cutter",
				Groups:   []string{"system:masters"},
			},
			"arn:aws:iam::012345678910:role/test-assumed-role": {
				RoleARN:  "arn:aws:iam::012345678910:role/test-assumed-role",
				Username: "test",
				Groups:   []string{"system:masters"},
			},
		},
		userMap: map[string]config.UserMapping{
			"arn:aws:iam::012345678910:user/donald": {
				UserARN:  "arn:aws:iam::012345678910:user/donald",
				Username: "donald",
				Groups:   []string{"system:masters"},
			},
		},
		accountMap: map[string]bool{
			"000000000000": true,
		},
		rootMap: map[string]config.RootMapping{},
	}

	actual, err := NewFileMapper(cfg)
	if err != nil {
		t.Errorf("Could not build FileMapper from test config: %v", err)
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("FileMapper does not match expected value.\nActual:   %v\nExpected: %v", actual, expected)
	}
}

func TestMap(t *testing.T) {
	fm, err := NewFileMapper(newConfig())
	if err != nil {
		t.Errorf("Could not build FileMapper from test config: %v", err)
	}

	identityArn := "arn:aws:iam::012345678910:role/test-role"
	identity := token.Identity{
		CanonicalARN: identityArn,
	}
	expected := &config.IdentityMapping{
		IdentityARN: identityArn,
		Username:    "shreyas",
		Groups:      []string{"system:masters"},
	}
	actual, err := fm.Map(&identity)
	if err != nil {
		t.Errorf("Could not map %s: %s", identityArn, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("FileMapper.Map() does not match expected value for roleMapping:\nActual:   %v\nExpected: %v", actual, expected)
	}

	identityArn = "arn:aws:iam::012345678910:role/awsreservedsso_cookiecutterpermissions_123123123"
	identity = token.Identity{
		CanonicalARN: identityArn,
	}
	expected = &config.IdentityMapping{
		IdentityARN: identityArn,
		Username:    "cookie-cutter",
		Groups:      []string{"system:masters"},
	}
	actual, err = fm.Map(&identity)
	if err != nil {
		t.Errorf("Could not map %s: %s", identityArn, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("FileMapper.Map() does not match expected value for roleArnLikeMapping:\nActual:   %v\nExpected: %v", actual, expected)
	}

	identityArn = "arn:aws:iam::012345678910:user/donald"
	identity = token.Identity{
		CanonicalARN: identityArn,
	}
	expected = &config.IdentityMapping{
		IdentityARN: identityArn,
		Username:    "donald",
		Groups:      []string{"system:masters"},
	}
	actual, err = fm.Map(&identity)
	if err != nil {
		t.Errorf("Could not map %s: %s", identityArn, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("FileMapper.Map() does not match expected value for userMapping:\nActual:   %v\nExpected: %v", actual, expected)
	}
}

func TestRootMap(t *testing.T) {
	cfg := config.Config{
		RootMappings: []config.RootMapping{
			{
				RootARN:  "arn:aws:iam::012345678910:root",
				Username: "root-admin",
				Groups:   []string{"system:masters"},
			},
		},
	}

	fm, err := NewFileMapper(cfg)
	if err != nil {
		t.Fatalf("Could not build FileMapper with root config: %v", err)
	}

	// Should match root principal
	identity := token.Identity{
		CanonicalARN: "arn:aws:iam::012345678910:root",
	}
	mapping, err := fm.Map(&identity)
	if err != nil {
		t.Fatalf("Root mapping did not match: %v", err)
	}
	if mapping.Username != "root-admin" {
		t.Errorf("Expected username root-admin, got %s", mapping.Username)
	}
	if mapping.Groups[0] != "system:masters" {
		t.Errorf("Expected group system:masters, got %s", mapping.Groups[0])
	}

	// Should not match a different account's root
	identity = token.Identity{
		CanonicalARN: "arn:aws:iam::999999999999:root",
	}
	_, err = fm.Map(&identity)
	if err == nil {
		t.Errorf("Root mapping unexpectedly matched different account")
	}

	// Should not match a role in the same account
	identity = token.Identity{
		CanonicalARN: "arn:aws:iam::012345678910:role/some-role",
	}
	_, err = fm.Map(&identity)
	if err == nil {
		t.Errorf("Root mapping unexpectedly matched a role ARN")
	}
}
