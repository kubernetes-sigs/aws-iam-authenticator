package dynamicfile

import (
	"os"
	"reflect"
	"testing"
	"time"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

var (
	testUser = config.UserMapping{UserARN: "arn:aws:iam::012345678912:user/matt", Username: "matlan", Groups: []string{"system:master", "dev"}}
	testRole = config.RoleMapping{RoleARN: "arn:aws:iam::012345678912:role/computer", Username: "computer", Groups: []string{"system:nodes"}}
)

func makeStore() DynamicFileMapStore {
	ms := DynamicFileMapStore{
		users:       make(map[string]config.UserMapping),
		roles:       make(map[string]config.RoleMapping),
		awsAccounts: make(map[string]interface{}),
		filename:    "test.txt",
	}
	ms.users["arn:aws:iam::012345678912:user/matt"] = testUser
	ms.roles["arn:aws:iam::012345678912:role/computer"] = testRole
	ms.awsAccounts["123"] = nil
	return ms
}

func TestUserMapping(t *testing.T) {
	ms := makeStore()
	user, err := ms.UserMapping("arn:aws:iam::012345678912:user/matt")
	if err != nil {
		t.Errorf("Could not find user 'matt' in map")
	}
	if !reflect.DeepEqual(user, testUser) {
		t.Errorf("User for 'matt' does not match expected values. (Actual: %+v, Expected: %+v", user, testUser)
	}

	user, err = ms.UserMapping("nic")
	if err != UserNotFound {
		t.Errorf("UserNotFound error was not returned for user 'nic'")
	}
	if !reflect.DeepEqual(user, config.UserMapping{}) {
		t.Errorf("User value returned when user is not in the map was not empty: %+v", user)
	}
}

func TestRoleMapping(t *testing.T) {
	ms := makeStore()
	role, err := ms.RoleMapping("arn:aws:iam::012345678912:role/computer")
	if err != nil {
		t.Errorf("Could not find user 'instance in map")
	}
	if !reflect.DeepEqual(role, testRole) {
		t.Errorf("Role for 'instance' does not match expected value. (Acutal: %+v, Expected: %+v", role, testRole)
	}

	role, err = ms.RoleMapping("borg")
	if err != RoleNotFound {
		t.Errorf("RoleNotFound error was not returend for role 'borg'")
	}
	if !reflect.DeepEqual(role, config.RoleMapping{}) {
		t.Errorf("Role value returend when role is not in map was not empty: %+v", role)
	}
}

func TestAWSAccount(t *testing.T) {
	ms := makeStore()
	if !ms.AWSAccount("123") {
		t.Errorf("Expected aws account '123' to be in accounts list: %v", ms.awsAccounts)
	}
	if ms.AWSAccount("345") {
		t.Errorf("Did not expect account '345' to be in accounts list: %v", ms.awsAccounts)
	}
}

var origFileContent = `
{
  "mapRoles": [
    {
      "rolearn": "arn:aws:iam::000000000098:role/KubernetesAdmin",
      "username": "kubernetes-admin",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapUsers": [
    {
      "userarn": "arn:aws:iam::000000000000:user/Alice",
      "username": "alice",
      "groups": [
        "system:masters"
      ]
    },
    {
      "userarn": "arn:aws:iam::000000000002:user/Alice2",
      "username": "alice2",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapAccounts": [
    "012345678901",
    "456789012345"
  ]
}
`

var updatedFileContent = `
{
  "mapRoles": [
    {
      "rolearn": "arn:aws:iam::000000000098:role/KubernetesAdmin",
      "username": "kubernetes-admin",
      "groups": [
        "system:masters"
      ]
    },
    {
      "rolearn": "arn:aws:iam::000000000002:role/KubernetesNode",
      "username": "aws:{{AccountID}}:instance:{{SessionName}}",
      "groups": [
        "system:bootstrappers",
        "aws:instances"
      ]
    },
    {
      "rolearn": "arn:aws:iam::000000000003:role/KubernetesNode",
      "username": "system:node:{{EC2PrivateDNSName}}",
      "groups": [
        "system:nodes",
        "system:bootstrappers"
      ]
    },
    {
      "rolearn": "arn:aws:iam::000000000004:role/KubernetesAdmin",
      "username": "admin:{{SessionName}}",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapUsers": [
    {
      "userarn": "arn:aws:iam::000000000000:user/Alice",
      "username": "alice",
      "groups": [
        "system:masters"
      ]
    }
  ],
  "mapAccounts": [
    "012345678901",
    "456789012345"
  ]
}
`

func TestLoadDynamicFile(t *testing.T) {
	stopCh := make(chan struct{})
	defer close(stopCh)

	//When the file doesn't exist, expect mapping should be empty map
	ms, err := NewDynamicFileMapStore("/tmp/test.txt")
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}

	ms.startLoadDynamicFile(stopCh)
	time.Sleep(1 * time.Second)
	ms.mutex.RLock()
	if len(ms.roles) != 0 {
		t.Fatalf("testing failed as mapping should be empty since dynamic file doesn't exist")
	}
	if len(ms.users) != 0 {
		t.Fatalf("testing failed as mapping should be empty since dynamic file doesn't exist")
	}
	if len(ms.awsAccounts) != 0 {
		t.Fatalf("testing failed as mapping should be empty since dynamic file doesn't exist")
	}
	ms.mutex.RUnlock()

	//user create the dynamic file, expect that mapping should contain item
	time.Sleep(1 * time.Second)
	data := []byte(origFileContent)
	err = os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/test.txt")
	}

	time.Sleep(2 * time.Second)
	ms.mutex.RLock()
	if len(ms.roles) == 0 {
		t.Fatalf("testing failed as mapping should contain item since dynamic file has content")
	}
	if len(ms.users) == 0 {
		t.Fatalf("testing failed as mapping should contain item since dynamic file has content")
	}
	if len(ms.awsAccounts) == 0 {
		t.Fatalf("testing failed as mapping should contain item since dynamic file has content")
	}
	ms.mutex.RUnlock()
	//user update the dynamic file,expect mapping should be equal to expectedMapStore
	expectedData := []byte(updatedFileContent)
	err = os.WriteFile("/tmp/expected.txt", expectedData, 0600)

	expectedMapStore, err := NewDynamicFileMapStore("/tmp/expected.txt")
	if err != nil {
		t.Errorf("failed to create expected DynamicFileMapper")
	}
	expectedUserMappings, expectedRoleMappings, expectedAwsAccounts, err := ParseMap(expectedMapStore.filename)
	if err != nil {
		t.Errorf("failed to ParseMap expected DynamicFileMapper")
	}
	expectedMapStore.saveMap(expectedUserMappings, expectedRoleMappings, expectedAwsAccounts)

	time.Sleep(1 * time.Second)

	//modify the dynamic file
	data = []byte(updatedFileContent)
	err = os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to modify a local file /tmp/test.txt")
	}
	time.Sleep(1 * time.Second)
	ms.mutex.RLock()
	if !reflect.DeepEqual(expectedMapStore.roles, ms.roles) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	if !reflect.DeepEqual(expectedMapStore.users, ms.users) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	if !reflect.DeepEqual(expectedMapStore.awsAccounts, ms.awsAccounts) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	ms.mutex.RUnlock()
	//user delete the dynamic file, expect mapping should be empty
	err = os.Remove("/tmp/test.txt")
	if err != nil {
		t.Errorf("failed to delete a local file /tmp/test.txt")
	}
	time.Sleep(1 * time.Second)
	ms.mutex.RLock()
	if len(ms.roles) != 0 {
		t.Fatalf("testing failed as mapping doesn't update after file deletion")
	}
	if len(ms.users) != 0 {
		t.Fatalf("testing failed as mapping doesn't update after file deletion")
	}
	if len(ms.awsAccounts) != 0 {
		t.Fatalf("testing failed as mapping doesn't update after file deletion")
	}
	ms.mutex.RUnlock()
	//user add file back, expect mapping should be equal to expectedMap
	time.Sleep(1 * time.Second)
	data = []byte(updatedFileContent)
	err = os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/test.txt")
	}

	time.Sleep(2 * time.Second)
	ms.mutex.RLock()
	if !reflect.DeepEqual(expectedMapStore.roles, ms.roles) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	if !reflect.DeepEqual(expectedMapStore.users, ms.users) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	if !reflect.DeepEqual(expectedMapStore.awsAccounts, ms.awsAccounts) {
		t.Fatalf("testing failed as mapping doesn't update after file modification")
	}
	ms.mutex.RUnlock()
	//clean test files
	defer os.Remove("/tmp/test.txt")
	defer os.Remove("/tmp/expected.txt")

}

func TestParseMap(t *testing.T) {

	data := []byte(origFileContent)
	err := os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/test.txt")
	}
	ms, err := NewDynamicFileMapStore("/tmp/test.txt")
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}

	u, r, a, err := ParseMap(ms.filename)
	if err != nil {
		t.Fatal(err)
	}

	origUserMappings := []config.UserMapping{
		{UserARN: "arn:aws:iam::000000000000:user/Alice", Username: "alice", Groups: []string{"system:masters"}},
		{UserARN: "arn:aws:iam::000000000002:user/Alice2", Username: "alice2", Groups: []string{"system:masters"}},
	}
	origRoleMappings := []config.RoleMapping{
		{
			RoleARN:  "arn:aws:iam::000000000098:role/KubernetesAdmin",
			Username: "kubernetes-admin",
			Groups:   []string{"system:masters"},
		},
	}
	origAccounts := []string{"012345678901", "456789012345"}

	if !reflect.DeepEqual(u, origUserMappings) {
		t.Fatalf("unexpected userMappings %+v", u)
	}
	if !reflect.DeepEqual(r, origRoleMappings) {
		t.Fatalf("unexpected roleMappings %+v", r)
	}
	if !reflect.DeepEqual(a, origAccounts) {
		t.Fatalf("unexpected accounts %+v", a)
	}
	//clean testing files
	defer os.Remove("/tmp/test.txt")

}
