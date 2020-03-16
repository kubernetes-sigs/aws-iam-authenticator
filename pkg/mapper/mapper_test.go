package mapper

import (
	"testing"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

func TestValidateBackendMode(t *testing.T) {
	cases := []struct {
		name     string
		cfg      config.Config
		wantErrs bool
	}{
		{
			name: "valid backend mode",
			cfg: config.Config{
				BackendMode: []string{ModeMountedFile, ModeEKSConfigMap, ModeCRD},
			},
		},
		{
			name: "valid deprecated backend mode",
			cfg: config.Config{
				BackendMode: []string{ModeFile, ModeConfigMap},
			},
		},
		{
			name: "invalid backend mode",
			cfg: config.Config{
				BackendMode: []string{"ModeFoo"},
			},
			wantErrs: true,
		},
		{
			name: "empty backend mode",
			cfg: config.Config{
				BackendMode: []string{},
			},
			wantErrs: true,
		},
		{
			name: "duplicate backend mode",
			cfg: config.Config{
				BackendMode: []string{ModeMountedFile, ModeMountedFile},
			},
			wantErrs: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateBackendMode(c.cfg.BackendMode)
			if len(errs) > 0 && !c.wantErrs {
				t.Errorf("wanted no errors but got: %v", errs)
			} else if len(errs) == 0 && c.wantErrs {
				t.Errorf("wanted errors but got none")
			}
		})
	}
}
