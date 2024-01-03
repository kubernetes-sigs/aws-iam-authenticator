package configmap

import (
	"context"
	"strings"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

type ConfigMapMapper struct {
	*MapStore
}

var _ mapper.Mapper = &ConfigMapMapper{}

func NewConfigMapMapper(cfg config.Config) (*ConfigMapMapper, error) {
	ms, err := New(cfg.Master, cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	return &ConfigMapMapper{ms}, nil
}

func (m *ConfigMapMapper) Name() string {
	return mapper.ModeEKSConfigMap
}

func (m *ConfigMapMapper) Start(ctx context.Context) error {
	m.startLoadConfigMap(ctx)
	return nil
}

func (m *ConfigMapMapper) Map(identity *token.Identity) (*config.IdentityMapping, error) {
	canonicalARN := strings.ToLower(identity.CanonicalARN)

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

func (m *ConfigMapMapper) IsAccountAllowed(accountID string) bool {
	return m.AWSAccount(accountID)
}

func (m *ConfigMapMapper) UsernamePrefixReserveList() []string {
	return []string{}
}
