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
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize kubernetes-aws-authenticator by generating the key used by the server, a kubeconfig used by clients, the certificate used between both",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := getConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get config: %v\n", err)
			os.Exit(1)
		}

		localCfg := cfg
		localCfg.GenerateKubeconfigPath = "./kubernetes-aws-authenticator.kubeconfig"
		localCfg.StateDir = "./"

		err = localCfg.GenerateFiles()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not initialize: %v\n", err)
			os.Exit(1)
		}

		logrus.Infof("please put ./cert.pem to %s/cert.pem on kubernetes master node(s)", cfg.StateDir)
		logrus.Infof("please put ./key.pem to %s/key.pem on kubernetes master node(s)", cfg.StateDir)
		logrus.Info("please put kubernetes-aws-authenticator.kubeconfig to /etc/kubernetes/kubernetes-aws-authenticator.kubeconfig on kubernetes master node(s)")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
