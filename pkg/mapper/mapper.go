package mapper

import (
	"errors"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

const (
	ModeFile      string = "File"
	ModeConfigMap string = "ConfigMap"
	ModeCRD       string = "CRD"
)

var BackendModeChoices = []string{ModeFile, ModeConfigMap, ModeCRD}

var ErrNotMapped = errors.New("ARN is not mapped")

type Mapper interface {
	Name() string
	// Start must be non-blocking
	Start(stopCh <-chan struct{}) error
	Map(canonicalARN string) (*config.IdentityMapping, error)
	IsAccountAllowed(accountID string) bool
}
