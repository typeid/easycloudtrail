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
		RunE:  run,
	}
)

func init() {
	writeHistoryCmd.PersistentFlags().
		StringP("since", "s", "24h", "Since flag. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.")
	writeHistoryCmd.PersistentFlags().String("region", "", "Region to check")
	writeHistoryCmd.PersistentFlags().BoolP("raw", "r", false, "Show events in raw format")
	writeHistoryCmd.PersistentFlags().
		StringP("ignore-users", "i", "", "Users whose write events shall be excluded from the history as comma separated list.") //nolint:lll
}

func parseDurationToUTC(input string) (time.Time, error) {
	duration, err := time.ParseDuration(input)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC().Add(-duration), nil
}

func run(cmd *cobra.Command, args []string) error {
	since, _ := cmd.Flags().GetString("since")
	region, _ := cmd.Flags().GetString("region")
	raw, _ := cmd.Flags().GetBool("raw")
	ignoredUsersParam, _ := cmd.Flags().GetString("ignore-users")
	ignoredUsers := strings.Split(ignoredUsersParam, ",")

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
	err = awsClient.GetCloudTrailEvents(startTime, raw, ignoredUsers)
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

		err = awsClient.GetCloudTrailEvents(startTime, raw, ignoredUsers)
		if err != nil {
			return err
		}
	}

	return nil
}
