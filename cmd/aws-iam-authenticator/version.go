package main

import (
	"os"

	"github.com/spf13/cobra"
	goVersion "go.hein.dev/go-version"
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
		Run:   goVersion.Func(os.Stdout, shortened, version, commit, date),
	}
)

func init() {
	versionCmd.Flags().BoolVarP(&shortened, "short", "s", false, "Use shortened output for version information.")
	rootCmd.AddCommand(versionCmd)
}
