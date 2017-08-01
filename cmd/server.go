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

package cmd

import (
	"github.com/heptiolabs/kubernetes-aws-authenticator/pkg/server"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DefaultPort is the default localhost port (chosen randomly).
const DefaultPort = 21362

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Run a webhook validation server suitable that validates tokens using AWS IAM",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		config := server.Config{
			ClusterID:              viper.GetString("clusterID"),
			LocalhostPort:          viper.GetInt("server.port"),
			GenerateKubeconfigPath: viper.GetString("server.generateKubeconfig"),
			StateDir:               viper.GetString("server.stateDir"),
		}
		if err := viper.UnmarshalKey("server.mapRoles", &config.StaticRoleMappings); err != nil {
			logrus.WithError(err).Fatal("invalid server role mappings")
		}

		if config.ClusterID == "" {
			logrus.Fatal("cluster ID cannot be empty")
		}
		config.Run()
	},
}

func init() {
	viper.SetDefault("server.port", DefaultPort)

	serverCmd.Flags().String("generate-kubeconfig",
		"/etc/kubernetes/kubernetes-aws-authenticator.kubeconfig",
		"Output `path` where a generated webhook kubeconfig (for `--authentication-token-webhook-config-file`) will be stored (should be a hostPath mount).")
	viper.BindPFlag("server.generateKubeconfig", serverCmd.Flags().Lookup("generate-kubeconfig"))

	serverCmd.Flags().String("state-dir",
		"/var/kubernetes-aws-authenticator",
		"State `directory` for generated certificate and private key (should be a hostPath mount).")
	viper.BindPFlag("server.stateDir", serverCmd.Flags().Lookup("state-dir"))

	rootCmd.AddCommand(serverCmd)
}
