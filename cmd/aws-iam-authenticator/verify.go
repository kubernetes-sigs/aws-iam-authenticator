//go:build !no_verify

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
	"encoding/json"
	"fmt"
	"os"

	"sigs.k8s.io/aws-iam-authenticator/pkg/endpoints"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a token for debugging purpose",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		tok := viper.GetString("token")
		output := viper.GetString("output")
		clusterID := viper.GetString("clusterID")
		partition := viper.GetString("partition")

		if tok == "" {
			fmt.Fprintf(os.Stderr, "error: token not specified\n")
			cmd.Usage()
			os.Exit(1)
		}

		if clusterID == "" {
			fmt.Fprintf(os.Stderr, "error: cluster ID not specified\n")
			cmd.Usage()
			os.Exit(1)
		}

		instanceRegion := getInstanceRegion(context.Background())

		id, err := token.NewVerifier(clusterID, partition, instanceRegion, nil).Verify(tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not verify token: %v\n", err)
			os.Exit(1)
		}

		if output == "json" {
			value, err := json.MarshalIndent(id, "", "    ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not unmarshal token: %v\n", err)
			}
			fmt.Printf("%s\n", value)
		} else {
			fmt.Printf("%+v\n", id)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP("token", "t", "", "Token to verify")
	verifyCmd.Flags().StringP("output", "o", "", "Output format. Only `json` is supported currently.")
	viper.BindPFlag("token", verifyCmd.Flags().Lookup("token"))
	viper.BindPFlag("output", verifyCmd.Flags().Lookup("output"))

	verifyCmd.Flags().String("partition",
		endpoints.AwsPartitionID,
		fmt.Sprintf("The AWS partition. Must be one of: %v", endpoints.PARTITIONS))
	viper.BindPFlag("partition", verifyCmd.Flags().Lookup("partition"))

}

// Uses EC2 metadata to get the region. Returns "" if no region found.
func getInstanceRegion(ctx context.Context) string {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Warn] Unable to create config for metadata client, err: %v", err)
		panic(err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	getRegionOutput, err := imdsClient.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Warn] Region not found in instance metadata, err: %v\n", err)
		return ""
	}

	return getRegionOutput.Region
}
