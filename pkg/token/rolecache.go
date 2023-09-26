package token

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type IAMClient interface {
	ListRolesPages(input *iam.ListRolesInput, fn func(*iam.ListRolesOutput, bool) bool) error
}

// RoleCache Cache on first use IAM role cache which stores a map of Role ID -> ARN for lookup during verify
// operations. This solves the issue of assume-role ARNs not including the assumed role's path.
type RoleCache struct {
	awsClient   IAMClient
	searchRoles bool
	lastUpdate  time.Time
	idToFullARN map[string]string
	mutex       sync.RWMutex
}

// NewRoleCache Creates a RoleCache and returns it.
func NewRoleCache() *RoleCache {
	sess, err := session.NewSessionWithOptions(session.Options{SharedConfigState: session.SharedConfigEnable})
	var iamClient *iam.IAM
	if err != nil {
		logrus.WithError(err).Warn("failed to instantiate AWS session, disabling full role ARN lookup")
	} else {
		iamClient = iam.New(sess)
	}

	return &RoleCache{
		awsClient:   iamClient,
		searchRoles: iamClient != nil,
		lastUpdate:  time.Now().Add(-10 * time.Minute),
		idToFullARN: make(map[string]string),
		mutex:       sync.RWMutex{},
	}
}

// updateRoles Calls IAM ListRoles and updates the idToFullARN map.
func (r *RoleCache) updateRoles() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.lastUpdate = time.Now()

	newARNMap := make(map[string]string)

	err := r.awsClient.ListRolesPages(&iam.ListRolesInput{}, func(output *iam.ListRolesOutput, b bool) bool {
		for _, role := range output.Roles {
			newARNMap[*role.RoleId] = *role.Arn
		}
		return true
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			// If we don't have credentials or have access to ListRole then cancel searching roles in future
			switch aerr.Code() {
			case "NoCredentialProviders":
				logrus.WithError(aerr).Error("no credentials found to list IAM roles with, disabling role cache")
				r.searchRoles = false
			case "AccessDenied":
				logrus.WithError(aerr).Error("no access to IAM list role, disabling role cache")
				r.searchRoles = false
			default:
				// Treat as transient error
				logrus.WithError(aerr).Error("transient IAM role list failure")
			}
		} else {
			// Non aws error
			logrus.WithError(err).Error("failed to list IAM roles")
			r.searchRoles = false
		}

		return
	}

	r.idToFullARN = newARNMap
}

// CheckRoleID Takes a unique role ID and returns an ARN if found.
func (r *RoleCache) CheckRoleID(roleID string) (string, bool) {
	if !r.searchRoles {
		return "", false
	}

	if time.Now().Sub(r.lastUpdate) > 5*time.Minute {
		r.updateRoles()
	}

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	roleARN, exists := r.idToFullARN[roleID]
	return roleARN, exists
}
