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

func addDefaultFlags() {
	writeHistoryCmd.PersistentFlags().String("region", "", "Region to check")
	writeHistoryCmd.PersistentFlags().BoolP("raw", "r", false, "Show events in raw format")
	writeHistoryCmd.PersistentFlags().
		StringP("ignore-users", "i", "", "Users whose write events shall be excluded from the history as comma separated list.") //nolint:lll
	writeHistoryCmd.PersistentFlags().BoolP("toggle-event-ids", "", false, "Show event IDs in the output.")
}

func init() {
	addDefaultFlags()
	rootCmd.AddCommand(writeHistoryCmd)
	rootCmd.AddCommand(permissionDeniedHistoryCmd)
}
