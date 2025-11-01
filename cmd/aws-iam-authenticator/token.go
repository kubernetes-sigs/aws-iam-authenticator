//go:build !no_token

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

package main

import (
	"context"
	"fmt"
	"os"

	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Authenticate using AWS IAM and get token for Kubernetes",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		region := viper.GetString("region")
		roleARN := viper.GetString("role")
		externalID := viper.GetString("externalID")
		clusterID := viper.GetString("clusterID")
		tokenOnly := viper.GetBool("tokenOnly")
		forwardSessionName := viper.GetBool("forwardSessionName")
		sessionName := viper.GetString("sessionName")
		cache := viper.GetBool("cache")
		procCredTimeout := viper.GetDuration("processCredentialTimeout")

		if clusterID == "" {
			fmt.Fprintf(os.Stderr, "Error: cluster ID not specified\n")
			if err := cmd.Usage(); err != nil {
				fmt.Fprintf(os.Stderr, "Error displaying usage: %v\n", err)
			}
			os.Exit(1)
		}

		if forwardSessionName && sessionName != "" {
			fmt.Fprintf(os.Stderr, "Error: cannot specify both --forward-session-name and --session-name parameter\n")
			if err := cmd.Usage(); err != nil {
				fmt.Fprintf(os.Stderr, "Error displaying usage: %v\n", err)
			}
			os.Exit(1)
		}

		var tok token.Token
		var out string
		var err error
		gen, err := token.NewGenerator(forwardSessionName, cache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get token: %v\n", err)
			os.Exit(1)
		}

		tok, err = gen.GetWithOptions(context.Background(), &token.GetTokenOptions{
			ClusterID:                clusterID,
			AssumeRoleARN:            roleARN,
			AssumeRoleExternalID:     externalID,
			SessionName:              sessionName,
			Region:                   region,
			ProcessCredentialTimeout: procCredTimeout,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not get token: %v\n", err)
			os.Exit(1)
		}
		if tokenOnly {
			out = tok.Token
		} else {
			out = gen.FormatJSON(tok)
		}
		fmt.Println(out)
	},
}

func init() {
	rootCmd.AddCommand(tokenCmd)
	tokenCmd.Flags().String("region", "", "AWS region to use for assume role calls")
	tokenCmd.Flags().StringP("role", "r", "", "Assume an IAM Role ARN before signing this token")
	tokenCmd.Flags().StringP("external-id", "e", "", "External ID to pass when assuming the IAM Role")
	tokenCmd.Flags().StringP("session-name", "s", "", "Session name to pass when assuming the IAM Role")
	tokenCmd.Flags().Bool("token-only", false, "Return only the token for use with Bearer token based tools")
	tokenCmd.Flags().Bool("forward-session-name",
		false,
		"Enable mapping a federated sessions caller-specified-role-name attribute onto newly assumed sessions. NOTE: Only applicable when a new role is requested via --role")
	tokenCmd.Flags().Bool("cache", false, "Cache the credential on disk until it expires. Uses the aws profile specified by AWS_PROFILE or the default profile.")
	tokenCmd.Flags().Duration("process-credential-timeout", 0, "Timeout for AWS credential_process execution (e.g. 5m, 120s). 0 uses SDK default (1m).")
	if err := viper.BindPFlag("region", tokenCmd.Flags().Lookup("region")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "region", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("role", tokenCmd.Flags().Lookup("role")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "role", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("externalID", tokenCmd.Flags().Lookup("external-id")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "externalID", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("tokenOnly", tokenCmd.Flags().Lookup("token-only")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "tokenOnly", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("forwardSessionName", tokenCmd.Flags().Lookup("forward-session-name")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "forwardSessionName", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("sessionName", tokenCmd.Flags().Lookup("session-name")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "sessionName", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("cache", tokenCmd.Flags().Lookup("cache")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "cache", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("processCredentialTimeout", tokenCmd.Flags().Lookup("process-credential-timeout")); err != nil {
		fmt.Printf("Failed to bind flag '%s' - %+v\n", "processCredentialTimeout", err)
		os.Exit(1)
	}
	if err := viper.BindEnv("role", "DEFAULT_ROLE"); err != nil {
		fmt.Printf("Failed to bind env '%s' - %+v\n", "role", err)
		os.Exit(1)
	}
}
