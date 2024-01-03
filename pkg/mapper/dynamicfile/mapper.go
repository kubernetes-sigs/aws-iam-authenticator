package dynamicfile

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/errutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/fileutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
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

func (m *DynamicFileMapper) Start(ctx context.Context) error {
	fileutil.StartLoadDynamicFile(ctx, m.filename, m.DynamicFileMapStore)
	return nil
}

func (m *DynamicFileMapper) Map(identity *token.Identity) (*config.IdentityMapping, error) {
	canonicalARN := strings.ToLower(identity.CanonicalARN)

	key := canonicalARN
	if m.userIDStrict {
		key = identity.UserID
	}

	if roleMapping, err := m.RoleMapping(key); err == nil {
		if err := m.match(canonicalARN, roleMapping.RoleARN); err != nil {
			return nil, err
		}
		return roleMapping.IdentityMapping(identity), nil
	}

	if userMapping, err := m.UserMapping(key); err == nil {
		if err := m.match(canonicalARN, userMapping.UserARN); err != nil {
			return nil, err
		}
		return userMapping.IdentityMapping(identity), nil

	}
	return nil, errutil.ErrNotMapped
}

func (m *DynamicFileMapper) match(canonicalARN string, mappingARN string) error {
	if m.userIDStrict {
		// If ARN is provided, ARN must be validated along with UserID.  This avoids having to
		// support IAM user name/ARN changes. Without preventing this the mapping would look
		// invalid but still work and auditing would be difficult/impossible.
		strippedArn, _ := arn.StripPath(mappingARN)
		logrus.Infof("additional arn comparison for IAM arn. arn from STS response is %s, arn in mapper is %s",
			canonicalARN, strings.ToLower(strippedArn))
		if strippedArn != "" && canonicalARN != strings.ToLower(strippedArn) {
			return errutil.ErrIDAndARNMismatch
		}
		return nil
	}
	return nil
}

func (m *DynamicFileMapper) IsAccountAllowed(accountID string) bool {
	return m.AWSAccount(accountID)
}

func (m *DynamicFileMapper) UsernamePrefixReserveList() []string {
	return m.usernamePrefixReserveList
}
