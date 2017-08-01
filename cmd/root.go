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
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "kubernetes-aws-authenticator",
	Short: "A tool to authenticate to Kubernetes using AWS IAM credentials",
}

// Execute the CLI entrypoint
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Load configuration from `filename`")

	rootCmd.PersistentFlags().StringP(
		"cluster-id",
		"i",
		"",
		"Specify the cluster `ID`, a unique-per-cluster identifier for your kubernetes-aws-authenticator installation.",
	)
	viper.BindPFlag("clusterID", rootCmd.PersistentFlags().Lookup("cluster-id"))
	viper.BindEnv("clusterID", "KUBERNETES_AWS_AUTHENTICATOR_CLUSTER_ID")
}

func initConfig() {
	if cfgFile == "" {
		return
	}
	viper.SetConfigFile(cfgFile)
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Can't read configuration file %q: %v\n", cfgFile, err)
		os.Exit(1)
	}
}
