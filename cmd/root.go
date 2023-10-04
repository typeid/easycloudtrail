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

func AddDefaultFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("region", "", "Region to check")
	cmd.PersistentFlags().BoolP("raw", "r", false, "Show events in raw format")
	cmd.PersistentFlags().StringP("ignore-users", "i", "", "Users whose write events shall be excluded from the history as comma separated list.") //nolint:lll
	cmd.PersistentFlags().BoolP("toggle-event-ids", "", false, "Show event IDs in the output.")
}

func init() {
	rootCmd.AddCommand(writeHistoryCmd)
	rootCmd.AddCommand(permissionDeniedHistoryCmd)
}
