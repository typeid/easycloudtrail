package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "cloudtrailctl",
		Short: "Command line tool to quickly find changes made by customers on managed OpenShift clusters running on AWS.",
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {

	rootCmd.PersistentFlags().BoolP("direct", "d", false, "direct aws account (no jumproles)")

	rootCmd.AddCommand(historyCmd)
}
