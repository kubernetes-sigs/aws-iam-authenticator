package main

import (
	"fmt"

	"github.com/spf13/cobra"
	goversion "go.hein.dev/go-version"
)

var (
	shortened  = false
	version    = "unversioned"
	commit     = ""
	date       = ""
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Version will output the current build information",
		Long:  ``,
		Run: func(_ *cobra.Command, _ []string) {
			var response string
			versionOutput := goversion.New(version, commit, date)

			if shortened {
				response = versionOutput.ToShortened()
			} else {
				response = versionOutput.ToJSON()
			}
			fmt.Printf("%+v", response)
			return
		},
	}
)

func init() {
	versionCmd.Flags().BoolVarP(&shortened, "short", "s", false, "Use shortened output for version information.")
	rootCmd.AddCommand(versionCmd)
}
