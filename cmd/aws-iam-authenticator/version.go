package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
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
			ver := struct {
				Version string `json:"Version,omitempty"`
				Commit  string `json:"Commit,omitempty"`
				Date    string `json:"Date,omitempty"`
			}{pkg.Version, pkg.CommitID, date}

			switch {
			case shortened:
				fmt.Println(pkg.Version)
			case output == "json":
				if err := json.NewEncoder(os.Stdout).Encode(ver); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to encode version info to JSON - %+v\n", err)
					os.Exit(1)
				}
			case output == "yaml":
				if err := yaml.NewEncoder(os.Stdout).Encode(ver); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to encode version info to YAML - %+v\n", err)
					os.Exit(1)
				}
			default:
				fmt.Fprintln(os.Stderr, "unknown version option")
			}
		},
	}
)

func init() {
	versionCmd.Flags().BoolVarP(&shortened, "short", "s", false, "Print just the version number.")
	versionCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format. One of 'yaml' or 'json'.")
	rootCmd.AddCommand(versionCmd)
}
