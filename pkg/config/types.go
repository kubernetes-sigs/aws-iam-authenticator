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

// RoleMapping is a mapping of a single AWS Role ARN to a
// Kubernetes username and a list of Kubernetes groups
type RoleMapping struct {
	// RoleARN is the AWS Resource Name of the role. (e.g., "arn:aws:iam::000000000000:role/Foo").
	RoleARN string

	// Username is the Kubernetes username this role will authenticate as (e.g., `mycorp:foo`)
	Username string

	// UsernameFormat is the username pattern that this instances assuming this
	// role will have in Kubernetes. Can contain two template parameters,
	// "{{AccountID}}" is the 12 digit AWS ID and "{{SessionName}}" is the EC2
	// instance ID (e.g., "i-0123456789abcdef0") or the role name specified by the identity provider (e.g., "alice@example.com"
	// sanitized to "alice-example.com")
	UsernameFormat string

	// Groups is a list of Kubernetes groups this role will authenticate as (e.g., `system:masters`)
	Groups []string
}

// StaticUserMapping is a static mapping of a single AWS User ARN to a
// Kubernetes username and a list of Kubernetes groups
type StaticUserMapping struct {
	// UserARN is the AWS Resource Name of the user. (e.g., "arn:aws:iam::000000000000:user/Test").
	UserARN string

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

	// RoleMappings is a list of static or dynamic mappings from AWS IAM Role to
	// Kubernetes username+group.
	RoleMappings []RoleMapping

	// StaticUserMappings is a list of static mappings from AWS IAM User to
	// Kubernetes username+group.
	StaticUserMappings []StaticUserMapping
}
