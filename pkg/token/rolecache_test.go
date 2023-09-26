package token

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"testing"
)

type mockIAM struct {
	Called int
	Pages  []*iam.ListRolesOutput
	Err    error
}

func (m *mockIAM) ListRolesPages(input *iam.ListRolesInput, fn func(*iam.ListRolesOutput, bool) bool) error {
	m.Called++

	if m.Err != nil {
		return m.Err
	}

	lastItem := len(m.Pages) - 1
	for index, page := range m.Pages {
		fn(page, index == lastItem)
	}

	return nil
}

func getMockedRoleCache() (*RoleCache, *mockIAM) {
	r := NewRoleCache()
	m := &mockIAM{
		Pages: make([]*iam.ListRolesOutput, 0),
		Err:   nil,
	}
	r.awsClient = m
	r.searchRoles = true

	return r, m
}

func TestRoleCache_SuccessfulLookup(t *testing.T) {
	r, mock := getMockedRoleCache()

	mock.Pages = append(mock.Pages, &iam.ListRolesOutput{Roles: []*iam.Role{
		{RoleId: aws.String("someid1"), Arn: aws.String("somearn1")},
	}})

	lookupARN1, exists1 := r.CheckRoleID("someid1")
	if !exists1 {
		t.Fatal("ARN lookup 1 should have found an ARN")
	}
	if lookupARN1 != "somearn1" {
		t.Fatalf("ARN lookup 1 expected %s, got %s", "somearn1", lookupARN1)
	}
	if mock.Called != 1 {
		t.Fatal("IAM Mock called counter incorrect")
	}

	_, exists2 := r.CheckRoleID("someid2")
	if exists2 {
		t.Fatal("ARN lookup 2 should have not found an ARN")
	}
	if mock.Called != 1 {
		t.Fatalf("IAM Mock called erronously, counter should be %d but got %d", 1, mock.Called)
	}
}

func TestRoleCache_AccessDenied(t *testing.T) {
	r, mock := getMockedRoleCache()

	mock.Err = awserr.New("AccessDenied", "access denied", errors.New("some access denied error"))
	_, exists := r.CheckRoleID("someid1")
	if exists {
		t.Fatal("ARN lookup should have not found an ARN")
	}
	if mock.Called != 1 {
		t.Fatal("Mock lookup was not called")
	}
	if r.searchRoles {
		t.Fatal("Role searching should have been permanently disabled")
	}
}

func TestRoleCache_NoCredentialProviders(t *testing.T) {
	r, mock := getMockedRoleCache()

	mock.Err = awserr.New("NoCredentialProviders", "no creds", errors.New("no creds"))
	_, exists := r.CheckRoleID("someid1")
	if exists {
		t.Fatal("ARN lookup should have not found an ARN")
	}
	if mock.Called != 1 {
		t.Fatal("Mock lookup was not called")
	}
	if r.searchRoles {
		t.Fatal("Role searching should have been permanently disabled")
	}
}

func TestRoleCache_TransientError(t *testing.T) {
	r, mock := getMockedRoleCache()

	mock.Err = awserr.New("TransientError", "random error", errors.New("random error"))
	_, exists := r.CheckRoleID("someid1")
	if exists {
		t.Fatal("ARN lookup should have not found an ARN")
	}
	if mock.Called != 1 {
		t.Fatal("Mock lookup was not called")
	}
	if !r.searchRoles {
		t.Fatal("Role searching should not have been permanently disabled")
	}
}

func TestRoleCache_NonAWSError(t *testing.T) {
	r, mock := getMockedRoleCache()

	mock.Err = errors.New("non aws error")
	_, exists := r.CheckRoleID("someid1")
	if exists {
		t.Fatal("ARN lookup should have not found an ARN")
	}
	if mock.Called != 1 {
		t.Fatal("Mock lookup was not called")
	}
	if r.searchRoles {
		t.Fatal("Role searching should have been permanently disabled")
	}
}
