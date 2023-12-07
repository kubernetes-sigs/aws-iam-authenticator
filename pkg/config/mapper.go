package config

import (
	"strings"

	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

// IdentityMapping converts the RoleMapping into a generic IdentityMapping object
func (m *RoleMapping) IdentityMapping(identity *token.Identity) *IdentityMapping {
	return &IdentityMapping{
		IdentityARN: strings.ToLower(identity.CanonicalARN),
		Username:    m.Username,
		Groups:      m.Groups,
	}
}

// IdentityMapping converts the UserMapping into a generic IdentityMapping object
func (m *UserMapping) IdentityMapping(identity *token.Identity) *IdentityMapping {
	return &IdentityMapping{
		IdentityARN: strings.ToLower(identity.CanonicalARN),
		Username:    m.Username,
		Groups:      m.Groups,
	}
}
