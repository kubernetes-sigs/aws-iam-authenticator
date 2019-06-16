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
	"net"
	"net/http"

	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

// Server for the authentication webhook.
type Server struct {
	// Config is the whole configuration of aws-iam-authenticator used for valid keys and certs, kubeconfig, and so on
	config.Config
	httpServer http.Server
	listener   net.Listener

	iamclientset      clientset.Interface
	iamMappingsSynced cache.InformerSynced
	iamMappingsIndex  cache.Indexer
}
