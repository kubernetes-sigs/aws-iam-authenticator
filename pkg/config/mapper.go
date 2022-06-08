package config

import (
	"fmt"
	"regexp"
	"strings"

	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"

	"github.com/sirupsen/logrus"
)

// SSOArnLike returns a string that can be passed to arnlike.ArnLike to
// match canonicalized IAM Role ARNs against. Assumes Validate() has been called.
func (m *RoleMapping) SSOArnLike() string {
	if m.SSO == nil {
		return ""
	}

	var partition string
	if m.SSO.Partition == "" {
		partition = "aws"
	}

	return strings.ToLower(fmt.Sprintf("arn:%s:iam::%s:role/AWSReservedSSO_%s_*", partition, m.SSO.AccountID, m.SSO.PermissionSetName))
}

// Validate returns an error if the RoleMapping is not valid after being unmarshaled
func (m *RoleMapping) Validate() error {
	if m == nil {
		return fmt.Errorf("RoleMapping is nil")
	}

	if m.RoleARN == "" && m.SSO == nil {
		return fmt.Errorf("One of rolearn or SSO must be supplied")
	} else if m.RoleARN != "" && m.SSO != nil {
		return fmt.Errorf("Only one of rolearn or SSO can be supplied")
	}

	if m.SSO != nil {
		accountIDRegexp := regexp.MustCompile("^[0-9]{12}$")
		if !accountIDRegexp.MatchString(m.SSO.AccountID) {
			return fmt.Errorf("AccountID '%s' is not a valid AWS Account ID", m.SSO.AccountID)
		}

		// https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_PermissionSet.html
		permissionSetNameRegexp := regexp.MustCompile(`^[\w+=,.@-]{1,32}$`)
		if !permissionSetNameRegexp.MatchString(m.SSO.PermissionSetName) {
			return fmt.Errorf("PermissionSetName '%s' is not a valid AWS SSO PermissionSet Name", m.SSO.PermissionSetName)
		}

		switch m.SSO.Partition {
		case "aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b":
			// valid
		case "":
			// treated as "aws"
		default:
			return fmt.Errorf("Partition '%s' is not a valid AWS partition", m.SSO.Partition)
		}

		ssoArnLikeString := m.SSOArnLike()
		ok, err := arn.ArnLike(ssoArnLikeString, "arn:*:iam:*:*:role/*")
		if err != nil {
			return fmt.Errorf("SSOArnLike '%s' is not valid: %v", ssoArnLikeString, err)
		} else if !ok {
			return fmt.Errorf("SSOArnLike '%s' did not match an ARN for a canonicalized IAM Role", ssoArnLikeString)
		}
	}

	return nil
}

// Matches returns true if the supplied ARN or SSO settings matches
// this RoleMapping
func (m *RoleMapping) Matches(subject string) bool {
	if m.RoleARN != "" {
		return strings.ToLower(m.RoleARN) == strings.ToLower(subject)
	}

	// Assume the caller has called Validate(), which parses m.RoleARNLike
	// If subject is not parsable, then it cannot be a valid ARN anyway so
	// we can ignore the error here
	var ok bool
	if SSORoleMatchEnabled {
		var err error
		ok, err = arn.ArnLike(subject, m.SSOArnLike())
		if err != nil {
			logrus.Error("Could not parse subject ARN: ", err)
		}
	}
	return ok
}

// Key returns RoleARN or SSOArnLike(), whichever is not empty.
// Used to get a Key name for map[string]RoleMapping
func (m *RoleMapping) Key() string {
	if m.RoleARN != "" {
		return strings.ToLower(m.RoleARN)
	}
	return m.SSOArnLike()
}

// Validate returns an error if the UserMapping is not valid after being unmarshaled
func (m *UserMapping) Validate() error {
	if m == nil {
		return fmt.Errorf("UserMapping is nil")
	}

	if m.UserARN == "" {
		return fmt.Errorf("Value for userarn must be supplied")
	}

	return nil
}

// Matches returns true if the supplied ARN string matche this UserMapping
func (m *UserMapping) Matches(subject string) bool {
	return strings.ToLower(m.UserARN) == strings.ToLower(subject)
}

// Key returns UserARN.
// Used to get a Key name for map[string]UserMapping
func (m *UserMapping) Key() string {
	return m.UserARN
}
