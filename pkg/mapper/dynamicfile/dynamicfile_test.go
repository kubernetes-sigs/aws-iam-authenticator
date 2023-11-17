package dynamicfile

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/fileutil"
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
	ms.roles["UserId001"] = testRole
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
	role, err := ms.RoleMapping("UserId001")
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
      ],
      "userid": "userid678"
    }
  ],
  "mapUsers": [
    {
      "userarn": "arn:aws:iam::000000000000:user/Alice",
      "username": "alice",
      "groups": [
        "system:masters"
      ],
      "userid": "userid135"
    },
    {
      "userarn": "arn:aws:iam::000000000002:user/Alice2",
      "username": "alice2",
      "groups": [
        "system:masters"
      ],
      "userid": "userid136"
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
      ],
      "userid": "userid12359"
    },
    {
      "rolearn": "arn:aws:iam::000000000002:role/KubernetesNode",
      "username": "aws:{{AccountID}}:instance:{{SessionName}}",
      "groups": [
        "system:bootstrappers",
        "aws:instances"
      ],
      "userid": "userid123"
    },
    {
      "rolearn": "arn:aws:iam::000000000003:role/KubernetesNode",
      "username": "system:node:{{EC2PrivateDNSName}}",
      "groups": [
        "system:nodes",
        "system:bootstrappers"
      ],
      "userid": "userid008"
    },
    {
      "rolearn": "arn:aws:iam::000000000004:role/KubernetesAdmin",
      "username": "admin:{{SessionName}}",
      "groups": [
        "system:masters"
      ],
      "userid": "userid777"
    }
  ],
  "mapUsers": [
    {
      "userarn": "arn:aws:iam::000000000000:user/Alice",
      "username": "alice",
      "groups": [
        "system:masters"
      ],
      "userid": "userid008"
    }
  ],
  "mapAccounts": [
    "012345678901",
    "456789012345"
  ]
}
`

func TestUserIdStrict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//When the file doesn't exist, expect mapping should be empty map
	cfg := config.Config{
		DynamicFileUserIDStrict: true,
		DynamicFilePath:         "/tmp/test.txt",
	}
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}
	data := []byte(origFileContent)
	err = os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/test.txt")
	}
	fileutil.StartLoadDynamicFile(ctx, ms.filename, ms)
	time.Sleep(1 * time.Second)
	ms.mutex.RLock()
	for key, _ := range ms.roles {
		if key[0:6] != "userid" {
			t.Errorf("failed to generate key for userIDStrict")
		}
	}
	ms.mutex.RUnlock()
	//clean test files
	defer os.Remove("/tmp/test.txt")
}

func TestWithoutUserIdStrict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//When the file doesn't exist, expect mapping should be empty map
	cfg := config.Config{
		DynamicFileUserIDStrict: false,
		DynamicFilePath:         "/tmp/test.txt",
	}
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}
	data := []byte(origFileContent)
	err = os.WriteFile("/tmp/test.txt", data, 0600)
	if err != nil {
		t.Errorf("failed to create a local file /tmp/test.txt")
	}
	fileutil.StartLoadDynamicFile(ctx, ms.filename, ms)
	time.Sleep(1 * time.Second)
	ms.mutex.RLock()
	for key, _ := range ms.roles {
		if key[0:3] != "arn" {
			t.Errorf("failed to generate key for userIDStrict")
		}
	}
	ms.mutex.RUnlock()
	//clean test files
	defer os.Remove("/tmp/test.txt")
}

func TestLoadDynamicFileMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//When the file doesn't exist, expect mapping should be empty map
	cfg := config.Config{
		DynamicFileUserIDStrict: true,
		DynamicFilePath:         "/tmp/test.txt",
	}
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}

	fileutil.StartLoadDynamicFile(ctx, ms.filename, ms)
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
	os.WriteFile("/tmp/expected.txt", expectedData, 0600)

	cfg = config.Config{
		DynamicFileUserIDStrict: true,
		DynamicFilePath:         "/tmp/expected.txt",
	}
	expectedMapStore, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create expected DynamicFileMapper")
	}
	err = expectedMapStore.CallBackForFileLoad(context.Background(), []byte(updatedFileContent))
	if err != nil {
		t.Errorf("failed to ParseMap expected DynamicFileMapper")
	}

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

func TestCallBackForFileDeletion(t *testing.T) {
	cfg := config.Config{
		DynamicFileUserIDStrict: true,
		DynamicFilePath:         "/tmp/test.txt",
	}
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = ms.CallBackForFileDeletion(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(ms.users) != 0 {
		t.Fatalf("unexpected userMappings %+v", ms.users)
	}

	if len(ms.roles) != 0 {
		t.Fatalf("unexpected userMappings %+v", ms.roles)
	}

	if len(ms.awsAccounts) != 0 {
		t.Fatalf("unexpected userMappings %+v", ms.awsAccounts)
	}
}

func TestCallBackForFileLoad(t *testing.T) {

	data := []byte(origFileContent)
	cfg := config.Config{
		DynamicFileUserIDStrict: true,
		DynamicFilePath:         "/tmp/test.txt",
	}
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		t.Errorf("failed to create a DynamicFileMapper")
	}

	err = ms.CallBackForFileLoad(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}

	origUserMappings := []config.UserMapping{
		{UserARN: "arn:aws:iam::000000000000:user/Alice", Username: "alice", Groups: []string{"system:masters"}, UserId: "userid135"},
		{UserARN: "arn:aws:iam::000000000002:user/Alice2", Username: "alice2", Groups: []string{"system:masters"}, UserId: "userid136"},
	}
	origRoleMappings := []config.RoleMapping{
		{
			RoleARN:  "arn:aws:iam::000000000098:role/KubernetesAdmin",
			Username: "kubernetes-admin",
			Groups:   []string{"system:masters"},
			UserId:   "userid678",
		},
	}
	origAccounts := []string{"012345678901", "456789012345"}

	if len(ms.users) != len(origUserMappings) {
		t.Fatalf("unexpected userMappings %+v", ms.users)
	}

	for _, user := range origUserMappings {
		if _, ok := ms.users[user.UserId]; !ok {
			t.Fatalf("unexpected userMappings %+v", ms.users)
		}
	}

	if len(ms.roles) != len(origRoleMappings) {
		t.Fatalf("unexpected userMappings %+v", ms.roles)
	}

	for _, role := range origRoleMappings {
		if _, ok := ms.roles[role.UserId]; !ok {
			t.Fatalf("unexpected userMappings %+v", ms.roles)
		}
	}

	if len(ms.awsAccounts) != len(origAccounts) {
		t.Fatalf("unexpected userMappings %+v", ms.awsAccounts)
	}

	for _, account := range origAccounts {
		if _, ok := ms.awsAccounts[account]; !ok {
			t.Fatalf("unexpected userMappings %+v", ms.users)
		}
	}
}
