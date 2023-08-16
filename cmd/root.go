package cmd

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "easycloudtrail",
		Short: "Command line tool to query AWS cloudtrail with enhanced parameters",
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(writeHistoryCmd)
	rootCmd.AddCommand(permissionDeniedHistoryCmd)
}
