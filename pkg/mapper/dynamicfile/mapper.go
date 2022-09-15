package dynamicfile

import (
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"strings"
)

type DynamicFileMapper struct {
	*DynamicFileMapStore
}

var _ mapper.Mapper = &DynamicFileMapper{}

func NewDynamicFileMapper(cfg config.Config) (*DynamicFileMapper, error) {
	ms, err := NewDynamicFileMapStore(cfg.DynamicFilePath)
	if err != nil {
		return nil, err
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

func (m *DynamicFileMapper) Map(canonicalARN string) (*config.IdentityMapping, error) {
	canonicalARN = strings.ToLower(canonicalARN)

	rm, err := m.RoleMapping(canonicalARN)
	// TODO: Check for non Role/UserNotFound errors
	if err == nil {
		return &config.IdentityMapping{
			IdentityARN: canonicalARN,
			Username:    rm.Username,
			Groups:      rm.Groups,
		}, nil
	}

	um, err := m.UserMapping(canonicalARN)
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
