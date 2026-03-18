package configmap

import (
	"strings"

	"sigs.k8s.io/aws-iam-authenticator/pkg/errutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
)

// ConfigMapMapper maps IAM identities using the aws-auth Kubernetes ConfigMap.
type ConfigMapMapper struct { //nolint:revive // exported: stutter preserved for backwards compatibility
	*MapStore
}

var _ mapper.Mapper = &ConfigMapMapper{}

// NewConfigMapMapper creates a ConfigMapMapper using the provided configuration.
func NewConfigMapMapper(cfg config.Config) (*ConfigMapMapper, error) {
	ms, err := New(cfg.Master, cfg.Kubeconfig)
	if err != nil {
		return nil, err
	}
	return &ConfigMapMapper{ms}, nil
}

// Name returns the name of this mapper mode.
func (m *ConfigMapMapper) Name() string {
	return mapper.ModeEKSConfigMap
}

// Start begins watching the aws-auth ConfigMap and stops when stopCh is closed.
func (m *ConfigMapMapper) Start(stopCh <-chan struct{}) error {
	m.startLoadConfigMap(stopCh)
	return nil
}

// Map maps an IAM identity to a Kubernetes identity using the aws-auth ConfigMap.
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

	return nil, errutil.ErrNotMapped
}

// IsAccountAllowed returns true if the given AWS account ID is allowed by the ConfigMap.
func (m *ConfigMapMapper) IsAccountAllowed(accountID string) bool {
	return m.AWSAccount(accountID)
}

// UsernamePrefixReserveList returns the list of reserved username prefixes for this mapper.
func (m *ConfigMapMapper) UsernamePrefixReserveList() []string {
	return []string{}
}
