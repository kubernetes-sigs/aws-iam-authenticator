/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"k8s.io/component-base/featuregate"
)

const (
	// ConfiguredInitDirectories enables placing files directly in configured
	// directories with init
	ConfiguredInitDirectories featuregate.Feature = "ConfiguredInitDirectories"
	// IAMIdentityMappingCRD enables using CRDs to manage allowed users
	IAMIdentityMappingCRD featuregate.Feature = "IAMIdentityMappingCRD"
	// SSORoleMatch enables matching roles managed by AWS SSO, with handling
	// for their randomly generated suffixes
	SSORoleMatch featuregate.Feature = "SSORoleMatch"
)

var (
	SSORoleMatchEnabled bool
)

var DefaultFeatureGates = map[featuregate.Feature]featuregate.FeatureSpec{
	ConfiguredInitDirectories: {Default: false, PreRelease: featuregate.Alpha},
	IAMIdentityMappingCRD:     {Default: false, PreRelease: featuregate.Alpha},
	SSORoleMatch:              {Default: false, PreRelease: featuregate.Alpha},
}
