package configmap

import (
	"context"
	"io/ioutil"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

var log = logrus.New()

func TestConfigMap(t *testing.T) {
	log.Level = logrus.DebugLevel

	nodeRoleARN := "arn:aws:iam::555555555555:role/devel-worker-nodes-NodeInstanceRole-74RF4UBDUKL6"
	adminUserARN := "arn:aws:iam::555555555555:user/admin"
	validRoleMappings := []config.RoleMapping{
		{
			RoleARN:  nodeRoleARN,
			Username: "system:node:{{EC2PrivateDNSName}}",
			Groups:   []string{"system:bootstrappers", "system:nodes"},
		},
	}
	validUserMappings := []config.UserMapping{
		{
			UserARN:  adminUserARN,
			Username: "admin",
			Groups:   []string{"system:masters"},
		},
	}
	validAWSAccounts := map[string]bool{
		"555555555555": true,
	}

	tests := []struct {
		configMapYaml        string
		expectedRoleMappings []config.RoleMapping
		expectedUserMappings []config.UserMapping
		expectedAWSAccounts  map[string]bool
		expectCreateError    bool
	}{
		// Success cases
		{
			// Valid aws-auth.yaml based on one in EKS documentation.
			"aws-auth.yaml", validRoleMappings, validUserMappings, validAWSAccounts, false,
		},
		{
			// RoLeArN instead of rolearn
			// parsing succeeds, values are case-insensitive for compatibility with upstream
			"aws-auth-crazy-case-keys.yaml", validRoleMappings, validUserMappings, validAWSAccounts, false,
		},
		{
			// roleARN instead of rolearn
			// parsing succeeds, values are case-insensitive for compatibility with upstream
			"aws-auth-open-source-case-keys.yaml", validRoleMappings, validUserMappings, validAWSAccounts, false,
		},
		// Fail cases -- ideally, validation should reject these before they reach us
		{
			// mapusers instead of mapUsers
			// parsing fails, top-level keys are case-sensitive
			"aws-auth-lower-case-top-keys.yaml", nil, nil, nil, false,
		},
		{
			// MaPuSeRs instead of mapUsers
			// parsing fails, top-level keys are case-sensitive
			"aws-auth-crazy-case-top-keys.yaml", nil, nil, nil, false,
		},
		{
			// an extra space ' ' before group '- system:nodes'
			// parsing succeeds, but groups is invalid 'system:bootstrappers - system:nodes'
			"aws-auth-space-out-of-place.yaml", []config.RoleMapping{
				{
					RoleARN:  nodeRoleARN,
					Username: "system:node:{{EC2PrivateDNSName}}",
					Groups:   []string{"system:bootstrappers - system:nodes"},
				},
			}, validUserMappings, validAWSAccounts, false,
		},
		{
			// a missing bar '|' after 'mapRoles:'
			// create fails, mapRoles is a top-level configMap key unlike upstream
			"aws-auth-missing-bar.yaml", nil, nil, nil, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.configMapYaml, func(t *testing.T) {
			cm, err := configMapFromYaml(tt.configMapYaml)
			if err != nil && !tt.expectCreateError {
				t.Errorf("error creating configMap from yaml: %v", err)
			} else if err == nil && tt.expectCreateError {
				t.Errorf("expected error creating configMap from yaml, got nothing")
			}

			cs := fake.NewSimpleClientset()
			ms := MapStore{}
			ms.configMap = cs.CoreV1().ConfigMaps("kube-system")

			stopCh := make(chan struct{})
			ms.startLoadConfigMap(stopCh)
			defer close(stopCh)

			time.Sleep(2 * time.Millisecond)
			_, _ = cs.CoreV1().ConfigMaps("kube-system").Create(context.TODO(), cm, metav1.CreateOptions{})
			time.Sleep(2 * time.Millisecond)

			for _, em := range tt.expectedRoleMappings {
				m, err := ms.RoleMapping(strings.ToLower(em.RoleARN))
				if err != nil {
					t.Errorf("%v", err)
				}
				if !reflect.DeepEqual(em, m) {
					t.Errorf("expected role mapping %v, got %v", em, m)
				}
			}
			ms.mutex.Lock()
			if len(tt.expectedRoleMappings) != len(ms.roles) {
				t.Errorf("expected role mappings %v, got %v", tt.expectedRoleMappings, ms.roles)
			}
			ms.mutex.Unlock()

			for _, em := range tt.expectedUserMappings {
				m, err := ms.UserMapping(strings.ToLower(em.UserARN))
				if err != nil {
					t.Errorf("%v", err)
				}
				if !reflect.DeepEqual(em, m) {
					t.Errorf("expected user mapping %v, got %v", em, m)
				}
			}
			ms.mutex.Lock()
			if len(tt.expectedUserMappings) != len(ms.users) {
				t.Errorf("expected user mappings %v, got %v", tt.expectedUserMappings, ms.users)
			}
			ms.mutex.Unlock()

			for accountID, eok := range tt.expectedAWSAccounts {
				ok := ms.AWSAccount(strings.ToLower(accountID))
				if eok != ok {
					t.Errorf("expected account %s %v, got %v", accountID, eok, ok)
				}
			}
			ms.mutex.Lock()
			if len(tt.expectedAWSAccounts) != len(ms.awsAccounts) {
				t.Errorf("expected accounts %v, got %v", tt.expectedAWSAccounts, ms.awsAccounts)
			}
			ms.mutex.Unlock()
		})
	}
}

func configMapFromYaml(fileName string) (*v1.ConfigMap, error) {
	var cm v1.ConfigMap
	data, err := ioutil.ReadFile(path.Join("./yaml/", fileName))
	if err != nil {
		return nil, err
	}

	json, err := utilyaml.ToJSON(data)
	if err != nil {
		return nil, err
	}
	err = runtime.DecodeInto(scheme.Codecs.UniversalDecoder(), json, &cm)
	if err != nil {
		return nil, err
	}
	return &cm, nil
}
