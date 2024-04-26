//go:build !no_add

/*
Copyright 2021 by the contributors.

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

package main

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmd_api "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/configmap/client"
	"sigs.k8s.io/yaml"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add IAM entity to an existing aws-auth configmap",
}

var addUserCmd = &cobra.Command{
	Use:   "user",
	Short: "add a user entity to an existing aws-auth configmap, not for CRD/file backends",
	Long:  "NOTE: this does not currently support the CRD and file backends",
	Run: func(cmd *cobra.Command, args []string) {
		if userARN == "" || userName == "" || len(groups) == 0 {
			fmt.Printf("invalid empty value in userARN %q, username %q, groups %q", userARN, userName, groups)
			os.Exit(1)
		}

		checkPrompt(fmt.Sprintf("add userarn %s, username %s, groups %s", userARN, userName, groups))
		cli := createClient()

		cm, err := cli.AddUser(&config.UserMapping{
			UserARN:  userARN,
			Username: userName,
			Groups:   groups,
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		b, err := yaml.Marshal(cm)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("updated configmap:\n\n%s\n", string(b))
	},
}

var addRoleCmd = &cobra.Command{
	Use:   "role",
	Short: "add a role entity to an existing aws-auth configmap, not for CRD/file backends",
	Long:  "NOTE: this does not currently support the CRD and file backends",
	Run: func(cmd *cobra.Command, args []string) {
		if roleARN == "" || userName == "" || len(groups) == 0 {
			fmt.Printf("invalid empty value in rolearn %q, username %q, groups %q", roleARN, userName, groups)
			os.Exit(1)
		}

		checkPrompt(fmt.Sprintf("add rolearn %s, username %s, groups %s", roleARN, userName, groups))
		cli := createClient()

		cm, err := cli.AddRole(&config.RoleMapping{
			RoleARN:  roleARN,
			Username: userName,
			Groups:   groups,
		})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		b, err := yaml.Marshal(cm)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("updated configmap:\n\n%s\n", string(b))
	},
}

func checkPrompt(action string) {
	if !prompt {
		return
	}

	msg := fmt.Sprintf("Ready to add %q, should we continue?", action)
	prompt := promptui.Select{
		Label: msg,
		Items: []string{
			"No, cancel it!",
			fmt.Sprintf("Yes, let's add %q!", action),
		},
	}
	idx, answer, err := prompt.Run()
	if err != nil {
		panic(err)
	}
	if idx != 1 {
		fmt.Printf("cancelled %q [index %d, answer %q]\n", action, idx, answer)
		os.Exit(0)
	}
}

func createClient() client.Client {
	if kubeconfigPath == "" {
		fmt.Println("empty kubeconfig")
		os.Exit(1)
	}

	var kcfg *restclient.Config
	var err error
	if kubeconfigContext != "" {
		kcfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{
				ExplicitPath: kubeconfigPath,
			},
			&clientcmd.ConfigOverrides{
				CurrentContext: kubeconfigContext,
				ClusterInfo:    clientcmd_api.Cluster{Server: masterURL},
			},
		).ClientConfig()
	} else {
		kcfg, err = clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
	}
	if err != nil {
		fmt.Println(err)
	}
	if kcfg == nil {
		defaultConfig := clientcmd.DefaultClientConfig
		kcfg, err = defaultConfig.ClientConfig()
		if kcfg == nil || err != nil {
			fmt.Printf("failed to create config from defaults %v\n", err)
			os.Exit(1)
		}
	}
	clientset, err := kubernetes.NewForConfig(kcfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return client.New(clientset.CoreV1().ConfigMaps("kube-system"))
}

var (
	prompt            bool
	masterURL         string
	kubeconfigPath    string
	kubeconfigContext string

	userARN  string
	userName string
	groups   []string
	roleARN  string
)

func init() {
	rootCmd.AddCommand(addCmd)
	addCmd.AddCommand(addUserCmd)
	addCmd.AddCommand(addRoleCmd)

	addCmd.PersistentFlags().BoolVar(&prompt, "prompt", true, "'false' to disable prompt'")
	addCmd.PersistentFlags().StringVar(&masterURL, "master-url", "", "kube-apiserver URL for creating Kubernetes client")
	addCmd.PersistentFlags().StringVar(&kubeconfigPath, "kubeconfig", "", "kubeconfig file path, if empty, it loads the default config")
	addCmd.PersistentFlags().StringVar(&kubeconfigContext, "kubeconfig-context", "", "kubeconfig context, if empty, it uses the default context")

	addUserCmd.PersistentFlags().StringVar(&userARN, "userarn", "", "A new user ARN")
	addUserCmd.PersistentFlags().StringVar(&userName, "username", "", "A new user name")
	addUserCmd.PersistentFlags().StringSliceVar(&groups, "groups", nil, "A new user groups")

	addRoleCmd.PersistentFlags().StringVar(&roleARN, "rolearn", "", "A new role ARN")
	addRoleCmd.PersistentFlags().StringVar(&userName, "username", "", "A new user name")
	addRoleCmd.PersistentFlags().StringSliceVar(&groups, "groups", nil, "A new role groups")
}
