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

package server

// StaticRoleMapping is a static mapping of a single AWS Role ARN to a
// Kubernetes username and a list of Kubernetes groups
type StaticRoleMapping struct {
	// RoleARN is the AWS Resource Name of the role. (e.g., "arn:aws:iam::000000000000:role/Foo").
	RoleARN string

	// Username is the Kubernetes username this role will authenticate as (e.g., `mycorp:foo`)
	Username string

	// Groups is a list of Kubernetes groups this role will authenticate as (e.g., `system:masters`)
	Groups []string
}

// Config specifies the configuration for a kubernetes-aws-authenticator server
type Config struct {
	// ClusterID is a unique-per-cluster identifier for your
	// kubernetes-aws-authenticator installation.
	ClusterID string

	// LocalhostPort is the TCP on which to listen for authentication checks
	// (on localhost).
	LocalhostPort int

	// GenerateKubeconfigPath is the output path where a generated webhook
	// kubeconfig (for `--authentication-token-webhook-config-file`) will be
	// stored.
	GenerateKubeconfigPath string

	// StateDir is the directory where generated certificates and private keys
	// will be stored. You want these persisted between runs so that your API
	// server webhook configuration doesn't change on restart.
	StateDir string

	// StaticRoleMappings is a list of static mappings from AWS IAM Role to
	// Kubernetes username+group.
	StaticRoleMappings []StaticRoleMapping
}
