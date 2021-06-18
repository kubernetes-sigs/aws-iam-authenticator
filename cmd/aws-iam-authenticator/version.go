package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"sigs.k8s.io/aws-iam-authenticator/pkg"
)

var (
	shortened  = false
	date       = ""
	output     = ""
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Version will output the current build information",
		Long:  ``,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Print("1")
			return
		},
	}
)

func init() {
	versionCmd.Flags().BoolVarP(&shortened, "short", "s", false, "Print just the version number.")
	versionCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format. One of 'yaml' or 'json'.")
	rootCmd.AddCommand(versionCmd)
}
