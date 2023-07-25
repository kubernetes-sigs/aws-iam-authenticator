package dynamicfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

type DynamicFileMapStore struct {
	mutex sync.RWMutex
	users map[string]config.UserMapping
	roles map[string]config.RoleMapping
	// Used as set.
	awsAccounts               map[string]interface{}
	filename                  string
	userIDStrict              bool
	usernamePrefixReserveList []string
}

type DynamicFileData struct {
	// RoleMappings is a list of mappings from AWS IAM Role to
	// Kubernetes username + groups.
	RoleMappings []config.RoleMapping `json:"mapRoles"`

	// UserMappings is a list of mappings from AWS IAM User to
	// Kubernetes username + groups.
	UserMappings []config.UserMapping `json:"mapUsers"`
	// AutoMappedAWSAccounts is a list of AWS accounts that are allowed without an explicit user/role mapping.
	// IAM ARN from these accounts automatically maps to the Kubernetes username.
	AutoMappedAWSAccounts []string `json:"mapAccounts"`
}

type ErrParsingMap struct {
	errors []error
}

func (err ErrParsingMap) Error() string {
	return fmt.Sprintf("error parsing dynamic file: %v", err.errors)
}

func NewDynamicFileMapStore(cfg config.Config) (*DynamicFileMapStore, error) {
	ms := DynamicFileMapStore{}
	ms.filename = cfg.DynamicFilePath
	ms.userIDStrict = cfg.DynamicFileUserIDStrict
	return &ms, nil
}

func (ms *DynamicFileMapStore) saveMap(
	userMappings []config.UserMapping,
	roleMappings []config.RoleMapping,
	awsAccounts []string) {

	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	ms.users = make(map[string]config.UserMapping)
	ms.roles = make(map[string]config.RoleMapping)
	ms.awsAccounts = make(map[string]interface{})

	for _, user := range userMappings {
		key, _ := arn.Canonicalize(strings.ToLower(user.UserARN))
		if ms.userIDStrict {
			key = user.UserId
		}
		ms.users[key] = user
	}
	for _, role := range roleMappings {
		key, _ := arn.Canonicalize(strings.ToLower(role.RoleARN))
		if ms.userIDStrict {
			key = role.UserId
		}
		ms.roles[key] = role
	}
	for _, awsAccount := range awsAccounts {
		ms.awsAccounts[awsAccount] = nil
	}
}

// UserNotFound is the error returned when the user is not found in the config map.
var UserNotFound = errors.New("User not found in dynamic file")

// RoleNotFound is the error returned when the role is not found in the config map.
var RoleNotFound = errors.New("Role not found in dynamic file")

func (ms *DynamicFileMapStore) UserMapping(arn string) (config.UserMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if user, ok := ms.users[arn]; !ok {
		return config.UserMapping{}, UserNotFound
	} else {
		return user, nil
	}
}

func (ms *DynamicFileMapStore) RoleMapping(arn string) (config.RoleMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if role, ok := ms.roles[arn]; !ok {
		return config.RoleMapping{}, RoleNotFound
	} else {
		return role, nil
	}
}

func (ms *DynamicFileMapStore) AWSAccount(id string) bool {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	_, ok := ms.awsAccounts[id]
	return ok
}

func (ms *DynamicFileMapStore) LogMapping() {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	for _, user := range ms.users {
		logrus.Info(user)
	}
	for _, role := range ms.roles {
		logrus.Info(role)
	}
	for awsAccount, _ := range ms.awsAccounts {
		logrus.Info(awsAccount)
	}
}

func (ms *DynamicFileMapStore) CallBackForFileLoad(dynamicContent []byte) error {
	errs := make([]error, 0)
	userMappings := make([]config.UserMapping, 0)
	roleMappings := make([]config.RoleMapping, 0)
	var dynamicFileData DynamicFileData
	err := json.Unmarshal(dynamicContent, &dynamicFileData)
	if err != nil {
		logrus.Error("ParseMap: could not unmarshal dynamic file.")
		return err
	}

	for _, userMapping := range dynamicFileData.UserMappings {
		key := userMapping.UserARN
		if ms.userIDStrict {
			key = userMapping.UserId
		}
		if key == "" {
			errs = append(errs, fmt.Errorf("Value for userarn or userid(if dynamicfileUserIDStrict = true) must be supplied"))
		} else {
			userMappings = append(userMappings, userMapping)
		}
	}

	for _, roleMapping := range dynamicFileData.RoleMappings {
		key := roleMapping.RoleARN
		if ms.userIDStrict {
			key = roleMapping.UserId
		}
		if key == "" {
			errs = append(errs, fmt.Errorf("Value for rolearn or userid(if dynamicfileUserIDStrict = true) must be supplied"))
		} else {
			roleMappings = append(roleMappings, roleMapping)
		}
	}

	awsAccounts := dynamicFileData.AutoMappedAWSAccounts[:]

	if len(errs) > 0 {
		logrus.Warnf("ParseMap: Errors parsing dynamic file: %+v", errs)
		err = ErrParsingMap{errors: errs}
		return err
	}
	ms.saveMap(userMappings, roleMappings, awsAccounts)
	return nil
}

func (ms *DynamicFileMapStore) CallBackForFileDeletion() error {
	userMappings := make([]config.UserMapping, 0)
	roleMappings := make([]config.RoleMapping, 0)
	awsAccounts := make([]string, 0)
	ms.saveMap(userMappings, roleMappings, awsAccounts)
	return nil
}
