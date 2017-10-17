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

import (
	"github.com/heptiolabs/kubernetes-aws-authenticator/pkg/config"
)

// StaticRoleMapping is a static mapping of a single AWS Role ARN to a
// Kubernetes username and a list of Kubernetes groups
type Server struct {
	// Config is the whole configuration of kubernetes-aws-authenticator used for valid keys and certs, kubeconfig, and so on
	config.Config
}
