// Package mapper defines the Mapper interface and backend mode constants for IAM identity mapping.
package mapper

import (
	"fmt"

	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

// Backend mode constants define the available IAM mapping backends.
const (
	// Deprecated: use ModeMountedFile instead
	ModeFile string = "File"
	// Deprecated: use ModeEKSConfigMap instead
	ModeConfigMap string = "ConfigMap"

	ModeMountedFile string = "MountedFile"

	ModeEKSConfigMap string = "EKSConfigMap"

	ModeCRD string = "CRD"

	ModeDynamicFile string = "DynamicFile"
)

// ValidBackendModeChoices lists all valid backend mode identifiers.
var (
	ValidBackendModeChoices      = []string{ModeFile, ModeConfigMap, ModeMountedFile, ModeEKSConfigMap, ModeCRD, ModeDynamicFile}
	DeprecatedBackendModeChoices = map[string]string{
		ModeFile:      ModeMountedFile,
		ModeConfigMap: ModeEKSConfigMap,
	}
	BackendModeChoices = []string{ModeMountedFile, ModeEKSConfigMap, ModeCRD, ModeDynamicFile}
)

// DefaultReservedUsernamePrefixes are username prefixes that are always reserved,
// regardless of operator configuration. A mapped username (from aws-auth
// mapRoles/mapUsers or any other backend) must not begin with one of these.
var DefaultReservedUsernamePrefixes = []string{"system:"}

// ReservedUsernamePrefixes returns the reserved username prefixes for the given
// backend mode: the always-reserved defaults merged with any operator-configured
// prefixes from cfg.ReservedPrefixConfig, de-duplicated.
func ReservedUsernamePrefixes(cfg config.Config, mode string) []string {
	prefixes := sets.NewString(DefaultReservedUsernamePrefixes...)
	if value, exists := cfg.ReservedPrefixConfig[mode]; exists {
		prefixes.Insert(value.UsernamePrefixReserveList...)
	}
	return prefixes.List()
}

// Mapper is the interface implemented by all IAM identity mapping backends.
type Mapper interface {
	Name() string
	// Start must be non-blocking
	Start(stopCh <-chan struct{}) error
	Map(identity *token.Identity) (*config.IdentityMapping, error)
	IsAccountAllowed(accountID string) bool
	UsernamePrefixReserveList() []string
}

// ValidateBackendMode returns errors for any unrecognized backend mode strings.
func ValidateBackendMode(modes []string) []error {
	var errs []error

	validModes := sets.NewString(ValidBackendModeChoices...)
	for _, mode := range modes {
		if !validModes.Has(mode) {
			errs = append(errs, fmt.Errorf("backend-mode %q is not a valid mode", mode))
		}
	}

	for _, mode := range modes {
		if replacementMode, ok := DeprecatedBackendModeChoices[mode]; ok {
			logrus.Warningf("warning: backend-mode %q is deprecated, use %q instead", mode, replacementMode)
		}
	}

	if len(modes) != sets.NewString(modes...).Len() {
		errs = append(errs, fmt.Errorf("backend-mode %q has duplicates", modes))
	}

	if len(modes) == 0 {
		errs = append(errs, fmt.Errorf("at least one backend-mode must be specified"))
	}

	return errs
}
