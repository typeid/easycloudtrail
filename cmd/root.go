package cmd

import (
	"srep-cloudtrail/cmd/history"

	"github.com/spf13/cobra"
)

var (
	// Flags
	direct bool

	rootCmd = &cobra.Command{
		Use:   "cloudtrailctl",
		Short: "A util to quickly find changes made by customers on managed OpenShift clusters running on AWS.",
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {

	rootCmd.PersistentFlags().BoolVarP(&direct, "direct", "d", false, "direct aws account (no jumproles)")

	rootCmd.AddCommand(history.HistoryCmd)
}
