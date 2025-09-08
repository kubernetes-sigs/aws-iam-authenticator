package dynamicfile

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/errutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/fileutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
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

	dynamicFileInitDone bool
}

type DynamicFileData struct {
	// Time that the object takes from update time to load time
	LastUpdatedDateTime string `json:"LastUpdatedDateTime"`
	// Version is the version number of the update
	Version string `json:"Version"`
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
	ms.dynamicFileInitDone = false
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
		_, key, _ := arn.Canonicalize(strings.ToLower(user.UserARN))
		if ms.userIDStrict {
			key = user.UserId
		}
		ms.users[key] = user
	}
	for _, role := range roleMappings {
		_, key, _ := arn.Canonicalize(strings.ToLower(role.RoleARN))
		if ms.userIDStrict {
			key = role.UserId
		}
		ms.roles[key] = role
	}
	for _, awsAccount := range awsAccounts {
		ms.awsAccounts[awsAccount] = nil
	}
}

func (ms *DynamicFileMapStore) UserMapping(key string) (config.UserMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if user, ok := ms.users[key]; !ok {
		return config.UserMapping{}, errutil.ErrNotMapped
	} else {
		return user, nil
	}
}

func (ms *DynamicFileMapStore) RoleMapping(key string) (config.RoleMapping, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if role, ok := ms.roles[key]; !ok {
		return config.RoleMapping{}, errutil.ErrNotMapped
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
	for awsAccount := range ms.awsAccounts {
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
			errs = append(errs, fmt.Errorf("value for userarn or userid(if dynamicfileUserIDStrict = true) must be supplied"))
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
			errs = append(errs, fmt.Errorf("value for rolearn or userid(if dynamicfileUserIDStrict = true) must be supplied"))
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

	// when instance or container restarts, the dynamic file is (re)loaded and the latency metric is calculated
	// regardless if there was a change upstream, and thus can emit an incorrect latency value
	// so a workaround is to skip the first time the metric is calculated, and only emit metris after
	// as we know any subsequent calculations are from a valid change upstream
	if ms.dynamicFileInitDone {
		latency, err := fileutil.CalculateTimeDeltaFromUnixInSeconds(dynamicFileData.LastUpdatedDateTime)
		if err != nil {
			logrus.Errorf("error parsing latency for dynamic file: %v", err)
		} else {
			metrics.Get().E2ELatency.WithLabelValues("dynamic_file").Observe(float64(latency))
			logrus.WithFields(logrus.Fields{
				"Version": dynamicFileData.Version,
				"Type":    "dynamic_file",
				"Latency": latency,
			}).Infof("logging latency metric")
		}
	}
	ms.dynamicFileInitDone = true

	return nil
}

func (ms *DynamicFileMapStore) CallBackForFileDeletion() error {
	userMappings := make([]config.UserMapping, 0)
	roleMappings := make([]config.RoleMapping, 0)
	awsAccounts := make([]string, 0)
	ms.saveMap(userMappings, roleMappings, awsAccounts)
	return nil
}
