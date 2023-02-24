package dynamicfile

import (
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
	"strings"
)

type DynamicFileMapper struct {
	*DynamicFileMapStore
}

var _ mapper.Mapper = &DynamicFileMapper{}

func NewDynamicFileMapper(cfg config.Config) (*DynamicFileMapper, error) {
	ms, err := NewDynamicFileMapStore(cfg)
	if err != nil {
		return nil, err
	}
	if value, exists := cfg.ReservedPrefixConfig[mapper.ModeDynamicFile]; exists {
		ms.usernamePrefixReserveList = value.UsernamePrefixReserveList
	}
	return &DynamicFileMapper{ms}, nil
}

func (m *DynamicFileMapper) Name() string {
	return mapper.ModeDynamicFile
}

func (m *DynamicFileMapper) Start(stopCh <-chan struct{}) error {
	m.startLoadDynamicFile(stopCh)
	return nil
}

func (m *DynamicFileMapper) Map(identity *token.Identity) (*config.IdentityMapping, error) {
	canonicalARN := strings.ToLower(identity.CanonicalARN)
	key := canonicalARN
	if m.userIDStrict {
		key = identity.UserID
	}

	rm, err := m.RoleMapping(key)
	// TODO: Check for non Role/UserNotFound errors
	if err == nil {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    rm.Username,
			Groups:      rm.Groups,
		}, nil
	}

	um, err := m.UserMapping(key)
	if err == nil {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    um.Username,
			Groups:      um.Groups,
		}, nil
	}

	return nil, mapper.ErrNotMapped
}

func (m *DynamicFileMapper) IsAccountAllowed(accountID string) bool {
	return m.AWSAccount(accountID)
}

func (m *DynamicFileMapper) UsernamePrefixReserveList() []string {
	return m.usernamePrefixReserveList
}
