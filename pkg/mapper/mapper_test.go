package mapper

import (
	"reflect"
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

func TestReservedUsernamePrefixes(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		mode string
		want []string
	}{
		{
			name: "no reserved prefix config yields system: default",
			cfg:  config.Config{},
			mode: ModeEKSConfigMap,
			want: []string{"system:"},
		},
		{
			name: "operator prefixes are merged with system: default",
			cfg: config.Config{
				ReservedPrefixConfig: map[string]config.ReservedPrefixConfig{
					ModeEKSConfigMap: {
						BackendMode:               ModeEKSConfigMap,
						UsernamePrefixReserveList: []string{"eks:"},
					},
				},
			},
			mode: ModeEKSConfigMap,
			want: []string{"eks:", "system:"},
		},
		{
			name: "duplicate system: in operator config is de-duplicated",
			cfg: config.Config{
				ReservedPrefixConfig: map[string]config.ReservedPrefixConfig{
					ModeCRD: {
						BackendMode:               ModeCRD,
						UsernamePrefixReserveList: []string{"system:"},
					},
				},
			},
			mode: ModeCRD,
			want: []string{"system:"},
		},
		{
			name: "config for a different mode does not apply",
			cfg: config.Config{
				ReservedPrefixConfig: map[string]config.ReservedPrefixConfig{
					ModeEKSConfigMap: {
						BackendMode:               ModeEKSConfigMap,
						UsernamePrefixReserveList: []string{"eks:"},
					},
				},
			},
			mode: ModeCRD,
			want: []string{"system:"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ReservedUsernamePrefixes(c.cfg, c.mode)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("ReservedUsernamePrefixes() = %v, want %v", got, c.want)
			}
		})
	}
}
