package assumerole

import (
	"fmt"

	"srep-cloudtrail/pkg/utils/aws"
	"srep-cloudtrail/pkg/utils/ocm"
)

const (
	RhSreCcsAccessRolename   = "arn:aws:iam::snip:role/RH-SRE-CCS-Access"
	RhTechnicalSupportAccess = "arn:aws:iam::snip:role/RH-Technical-Support-Access"
	// Why? OrganizationAccountAccessRole = "OrganizationAccountAccessRole"
)

// jumpRoles will return an aws client or an error after trying to jump into
// support role
func JumpRoles(initialAwsClient *aws.Client, clusterID string, region string) (*aws.Client, error) {

	ocmClient, err := ocm.New()
	if err != nil {
		return nil, fmt.Errorf("could not initialize ocm client: %w", err)
	}

	customerAwsClient, err := AssumeSupportRoleChain(initialAwsClient, &ocmClient, clusterID, RhSreCcsAccessRolename, RhTechnicalSupportAccess, region)
	if err != nil {
		return nil, err
	}

	return &customerAwsClient, nil
}

// AssumeSupportRoleChain will jump between the current aws.Client to the customers aws.Client
func AssumeSupportRoleChain(awsClient *aws.Client, ocmClient *ocm.Client, clusterID string, ccsJumpRole string, supportRole string, region string) (aws.Client, error) {
	cluster, err := ocmClient.GetClusterInfo(clusterID)
	if err != nil {
		return aws.Client{}, fmt.Errorf("1 failed to get the cluster details :%w", err)
	}

	if region == "" {
		region = cluster.Region().ID()
	}

	internalID := cluster.ID()

	tempClient, err := awsClient.AssumeRole(ccsJumpRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("2 failed to assume into jump-role: %w", err)
	}

	jumpRoleClient, err := tempClient.AssumeRole(supportRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("3 failed to assume into jump-role: %w", err)
	}
	customerRole, err := ocmClient.GetSupportRoleARN(internalID)
	if err != nil {
		return aws.Client{}, fmt.Errorf("4 failed to get support Role: %w", err)
	}

	customerClient, err := jumpRoleClient.AssumeRole(customerRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("5 failed to assume into support-role: %w", err)
	}

	fmt.Printf("Successfully logged into customer account with role: %s\n", customerRole)

	return customerClient, nil
}
