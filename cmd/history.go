package cmd

import (
	"fmt"
	"time"

	"srep-cloudtrail/pkg/utils/assumerole"
	"srep-cloudtrail/pkg/utils/aws"

	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Get write events issued by the customer",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(historyCmd)
	historyCmd.PersistentFlags().StringP("since", "s", "24h", "Since flag. Valid time units are 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.")
	historyCmd.PersistentFlags().StringP("cluster-id", "c", "", "The ID of the cluster")

}

func parseDurationToUTC(input string) (time.Time, error) {
	duration, err := time.ParseDuration(input)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC().Add(-duration), nil
}

func getAssumeRoleAwsClient(clusterID string, region string) (aws.Client, error) {

	initialAwsClient, err := aws.GetAWSClient()
	if err != nil {
		return aws.Client{}, err
	}

	customerAwsClient, err := assumerole.JumpRoles(&initialAwsClient, clusterID, region)
	if err != nil {
		return aws.Client{}, err
	}

	return customerAwsClient, nil
}

func run(cmd *cobra.Command, args []string) error {
	direct, _ := cmd.Flags().GetBool("direct")
	since, _ := cmd.Flags().GetString("since")
	clusterID, _ := cmd.Flags().GetString("cluster-id")

	if !direct && clusterID == "" {
		return fmt.Errorf("Invalid usage: cluster-id flag is required when the direct flag is not set")
	}

	startTime, err := parseDurationToUTC(since)
	if err != nil {
		return err
	}

	fmt.Println("Checking history since", startTime, "- direct:", direct)

	var awsClient aws.Client
	if direct {
		awsClient, err = aws.GetAWSClient()
		if err != nil {
			return fmt.Errorf("could not initialize aws client: %w", err)
		}
	} else {
		awsClient, err = getAssumeRoleAwsClient(clusterID, "")
		if err != nil {
			return fmt.Errorf("could not initialize aws client: %w", err)
		}

	}

	fmt.Println("")
	fmt.Println("Fetching", awsClient.Region, "events...")
	awsClient.GetCloudTrailEvents(startTime)

	if awsClient.Region != "us-east=1" {
		fmt.Println("")
		fmt.Println("Fetching us-east-1 IAM events...")

		if direct {
			awsClient, err = aws.GetAWSClientWithRegion("us-east-1")
			if err != nil {
				return fmt.Errorf("could not initialize aws client: %w", err)
			}
		} else {
			awsClient, err = getAssumeRoleAwsClient(clusterID, "us-east-1")
			if err != nil {
				return fmt.Errorf("could not initialize aws client: %w", err)
			}

		}

		awsClient.GetCloudTrailEvents(startTime)
	}

	return nil
}
