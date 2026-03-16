// Package file implements a static YAML file backend for IAM identity mapping.
package file

import (
	"fmt"
	"strings"

	"sigs.k8s.io/aws-iam-authenticator/pkg/errutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
)

// FileMapper implements the Mapper interface using a static YAML file backend.
type FileMapper struct { //nolint:revive // exported: stutter preserved for backwards compatibility
	roleMap                   map[string]config.RoleMapping
	userMap                   map[string]config.UserMapping
	accountMap                map[string]bool
	usernamePrefixReserveList []string
}

var _ mapper.Mapper = &FileMapper{}

// NewFileMapper creates a new FileMapper from the given Config.
func NewFileMapper(cfg config.Config) (*FileMapper, error) {
	fileMapper := &FileMapper{
		roleMap:    make(map[string]config.RoleMapping),
		userMap:    make(map[string]config.UserMapping),
		accountMap: make(map[string]bool),
	}

	for _, m := range cfg.RoleMappings {
		err := m.Validate()
		if err != nil {
			return nil, err
		}
		if m.RoleARN != "" {
			_, canonicalizedARN, err := arn.Canonicalize(m.RoleARN)
			if err != nil {
				return nil, err
			}
			m.RoleARN = canonicalizedARN
		}
		fileMapper.roleMap[m.Key()] = m
	}
	for _, m := range cfg.UserMappings {
		err := m.Validate()
		if err != nil {
			return nil, err
		}
		var key string
		if m.UserARN != "" {
			_, canonicalizedARN, err := arn.Canonicalize(strings.ToLower(m.UserARN))
			if err != nil {
				return nil, fmt.Errorf("error canonicalizing ARN: %v", err)
			}
			key = canonicalizedARN
		}
		fileMapper.userMap[key] = m
	}
	for _, m := range cfg.AutoMappedAWSAccounts {
		fileMapper.accountMap[m] = true
	}
	if value, exists := cfg.ReservedPrefixConfig[mapper.ModeMountedFile]; exists {
		fileMapper.usernamePrefixReserveList = value.UsernamePrefixReserveList
	}
	return fileMapper, nil
}

// NewFileMapperWithMaps creates a FileMapper pre-populated with the given role and user mappings.
func NewFileMapperWithMaps(
	lowercaseRoleMap map[string]config.RoleMapping,
	lowercaseUserMap map[string]config.UserMapping,
	accountMap map[string]bool) *FileMapper {
	return &FileMapper{
		roleMap:    lowercaseRoleMap,
		userMap:    lowercaseUserMap,
		accountMap: accountMap,
	}
}

// Name returns the name of this mapper backend.
func (m *FileMapper) Name() string {
	return mapper.ModeMountedFile
}

// Start is a no-op for the file mapper.
func (m *FileMapper) Start(_ <-chan struct{}) error {
	return nil
}

// Map resolves an IAM identity to a Kubernetes identity mapping.
func (m *FileMapper) Map(identity *token.Identity) (*config.IdentityMapping, error) {
	canonicalARN := strings.ToLower(identity.CanonicalARN)
	for _, roleMapping := range m.roleMap {
		if roleMapping.Matches(canonicalARN) {
			return &config.IdentityMapping{
				IdentityARN: canonicalARN,
				Username:    roleMapping.Username,
				Groups:      roleMapping.Groups,
			}, nil
		}
	}
	if userMapping, exists := m.userMap[canonicalARN]; exists {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    userMapping.Username,
			Groups:      userMapping.Groups,
		}, nil
	}
	return nil, errutil.ErrNotMapped
}

// IsAccountAllowed returns true if the given AWS account ID is permitted.
func (m *FileMapper) IsAccountAllowed(accountID string) bool {
	return m.accountMap[accountID]
}

// UsernamePrefixReserveList returns username prefixes reserved by this mapper.
func (m *FileMapper) UsernamePrefixReserveList() []string {
	return m.usernamePrefixReserveList
}
