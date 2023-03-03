package history

import (
	"fmt"

	"srep-cloudtrail/pkg/utils/aws"
	// "srep-cloudtrail/pkg/utils/ocm"

	"github.com/spf13/cobra"
)

var HistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Get write events issued by the customer",
	RunE:  run,
}

func run(cmd *cobra.Command, args []string) error {

	direct, _ := cmd.Flags().GetBool("direct")

	fmt.Println("Checking history: ", direct)

	awsClient, err := aws.GetAWSClient()
	if err != nil {
		return fmt.Errorf("could not initialize aws client: %w", err)
	}
	fmt.Println(awsClient.Region)
	awsClient.GetCloudTrailEvents()

	// ocmClient, err := ocm.GetOCMClient()
	// if err != nil {
	// 	return fmt.Errorf("could not initialize ocm client: %w", err)
	// }

	// cluster, err := ocmClient.GetClusterInfo(externalClusterID)
	// if err != nil {
	// 	return fmt.Errorf("could not retrieve cluster info for %s: %w", externalClusterID, err)
	// }

	// // Try to jump into support role
	// customerAwsClient, err := assumerole.jumpRoles(awsClient, ocmClient, pdClient,
	// 	externalClusterID, cluster)
	// if err != nil {
	// 	return err
	// }

	return nil
}
