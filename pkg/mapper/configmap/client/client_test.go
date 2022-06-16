package client

import (
	"reflect"
	"strings"
	"testing"

	core_v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/configmap"
)

func TestAddUser(t *testing.T) {
	cli := makeTestClient(t,
		nil,
		[]config.RoleMapping{
			{RoleARN: "a", Username: "a", Groups: []string{"a"}},
		},
		nil,
	)
	newUser := config.UserMapping{UserARN: "a", Username: "a", Groups: []string{"a"}}
	cm, err := cli.AddUser(&newUser)
	if err != nil {
		t.Fatal(err)
	}
	u, _, _, err := configmap.ParseMap(cm.Data)
	if err != nil {
		t.Fatal(err)
	}
	updatedUser := u[0]
	if !reflect.DeepEqual(newUser, updatedUser) {
		t.Fatalf("unexpected updated user %+v", updatedUser)
	}

	if _, err := cli.AddRole(&config.RoleMapping{RoleARN: "a"}); err == nil || !strings.Contains(err.Error(), `cannot add duplicate role ARN`) {
		t.Fatal(err)
	}
}

func TestAddRole(t *testing.T) {
	cli := makeTestClient(t,
		[]config.UserMapping{
			{UserARN: "a", Username: "a", Groups: []string{"a"}},
		},
		nil,
		nil,
	)
	newRole := config.RoleMapping{RoleARN: "a", Username: "a", Groups: []string{"a"}}
	cm, err := cli.AddRole(&newRole)
	if err != nil {
		t.Fatal(err)
	}
	_, r, _, err := configmap.ParseMap(cm.Data)
	if err != nil {
		t.Fatal(err)
	}
	updatedRole := r[0]
	if !reflect.DeepEqual(newRole, updatedRole) {
		t.Fatalf("unexpected updated role %+v", updatedRole)
	}

	if _, err := cli.AddUser(&config.UserMapping{UserARN: "a"}); err == nil || !strings.Contains(err.Error(), `cannot add duplicate user ARN`) {
		t.Fatal(err)
	}

	cli = makeTestClient(t,
		nil,
		nil,
		nil,
	)
	newSSORole := config.RoleMapping{
		RoleARN: "",
		SSO: &config.SSOARNMatcher{
			PermissionSetName: "ViewOnlyAccess",
			AccountID:         "012345678912",
		},
		Username: "b",
		Groups:   []string{"b"}}
	cm, err = cli.AddRole(&newSSORole)
	if err != nil {
		t.Fatal(err)
	}
	_, srm, _, err := configmap.ParseMap(cm.Data)
	if err != nil {
		t.Fatal(err)
	}
	updatedRole = srm[0]
	if !reflect.DeepEqual(newSSORole, updatedRole) {
		t.Fatalf("unexpected updated role %+v", updatedRole)
	}

	cli = makeTestClient(t,
		nil,
		[]config.RoleMapping{newSSORole},
		nil,
	)
	if _, err := cli.AddRole(&newSSORole); err == nil || !strings.Contains(err.Error(), `cannot add duplicate role ARN`) {
		t.Fatal(err)
	}
}

func makeTestClient(
	t *testing.T,
	userMappings []config.UserMapping,
	roleMappings []config.RoleMapping,
	awsAccounts []string,
) Client {
	d, err := configmap.EncodeMap(userMappings, roleMappings, awsAccounts)
	if err != nil {
		t.Fatal(err)
	}
	return &client{
		getMap: func() (*core_v1.ConfigMap, error) {
			return &core_v1.ConfigMap{Data: d}, nil
		},
		updateMap: func(m *core_v1.ConfigMap) (*core_v1.ConfigMap, error) {
			return m, nil
		},
	}
}
