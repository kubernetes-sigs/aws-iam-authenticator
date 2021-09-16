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
				json.NewEncoder(os.Stdout).Encode(ver)
			case output == "yaml":
				yaml.NewEncoder(os.Stdout).Encode(ver)
			default:
				fmt.Fprintln(os.Stderr, "unknown version option")
			}
			return
		},
	}
)

func init() {
	versionCmd.Flags().BoolVarP(&shortened, "short", "s", false, "Print just the version number.")
	versionCmd.Flags().StringVarP(&output, "output", "o", "json", "Output format. One of 'yaml' or 'json'.")
	rootCmd.AddCommand(versionCmd)
}
