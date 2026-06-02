package crd

import (
	"reflect"
	"testing"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
)

func TestCRDMapperReservedPrefixesFromConfig(t *testing.T) {
	cfg := config.Config{
		ReservedPrefixConfig: map[string]config.ReservedPrefixConfig{
			mapper.ModeCRD: {
				BackendMode:               mapper.ModeCRD,
				UsernamePrefixReserveList: []string{"system:", "eks:"},
			},
		},
	}
	m := &CRDMapper{}
	if value, exists := cfg.ReservedPrefixConfig[mapper.ModeCRD]; exists {
		m.usernamePrefixReserveList = value.UsernamePrefixReserveList
	}
	got := m.UsernamePrefixReserveList()
	want := []string{"system:", "eks:"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UsernamePrefixReserveList() = %v, want %v", got, want)
	}
}

func TestCRDMapperReservedPrefixesEmptyByDefault(t *testing.T) {
	m := &CRDMapper{}
	if got := m.UsernamePrefixReserveList(); len(got) != 0 {
		t.Errorf("UsernamePrefixReserveList() = %v, want empty, got %v", got, got)
	}
}
