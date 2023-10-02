package cmd

import (
	"fmt"
	"strings"
	"time"

	"easycloudtrail/pkg/utils/aws"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

var (
	writeHistoryCmd = &cobra.Command{
		Use:   "write-history",
		Short: "Get cloudtrail write events",
		RunE:  runWriteHistory,
	}
)

func init() {
	AddDefaultFlags(writeHistoryCmd)
	// Redefine this flag as we want a different default.
	writeHistoryCmd.PersistentFlags().
		StringP("since", "s", "24h", "Since flag. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.")
}

func parseDurationToUTC(input string) (time.Time, error) {
	duration, err := time.ParseDuration(input)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC().Add(-duration), nil
}

func runWriteHistory(cmd *cobra.Command, args []string) error {
	since, _ := cmd.Flags().GetString("since")
	region, _ := cmd.Flags().GetString("region")
	raw, _ := cmd.Flags().GetBool("raw")
	ignoredUsersParam, _ := cmd.Flags().GetString("ignore-users")
	ignoredUsers := strings.Split(ignoredUsersParam, ",")
	toggleEventID, _ := cmd.Flags().GetBool("toggle-event-ids")

	startTime, err := parseDurationToUTC(since)
	if err != nil {
		return err
	}

	awsClient, err := aws.GetAWSClient(region)
	if err != nil {
		return fmt.Errorf("could not initialize aws client: %w", err)
	}

	callerIdentity, err := awsClient.StsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("could not get caller identity: %w", err)
	}
	fmt.Println(
		"Checking write event history since",
		startTime,
		"for AWS account",
		*callerIdentity.Account,
		"as",
		*callerIdentity.Arn,
	)

	fmt.Println("")
	fmt.Println("Fetching", awsClient.Region, "events...")
	err = awsClient.PrintCloudTrailWriteEvents(startTime, raw, ignoredUsers, toggleEventID)
	if err != nil {
		return err
	}

	if awsClient.Region != aws.DefaultRegion {
		fmt.Println("")
		fmt.Println("Fetching IAM events from", aws.DefaultRegion)

		awsClient, err = aws.GetAWSClientWithRegion(aws.DefaultRegion)
		if err != nil {
			return fmt.Errorf("could not initialize aws client: %w", err)
		}

		err = awsClient.PrintCloudTrailWriteEvents(startTime, raw, ignoredUsers, toggleEventID)
		if err != nil {
			return err
		}
	}

	return nil
}
