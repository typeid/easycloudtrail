package assumerole

import (
	"fmt"

	"srep-cloudtrail/pkg/utils/aws"

	v1 "github.com/openshift-online/ocm-sdk-go/clustersmgmt/v1"
)

type Service interface {
	// AWS
	AssumeRole(roleARN, region string) (aws.Client, error)

	// OCM
	GetClusterInfo(identifier string) (*v1.Cluster, error)
	GetSupportRoleARN(clusterID string) (string, error)
}

type Client struct {
	Service
}

// AssumeSupportRoleChain will jump between the current aws.Client to the customers aws.Client
func (c Client) AssumeSupportRoleChain(identifier, ccsJumpRole, supportRole string) (aws.Client, error) {
	cluster, err := c.GetClusterInfo(identifier)
	if err != nil {
		return aws.Client{}, fmt.Errorf("1 failed to get the cluster details :%w", err)
	}
	region := cluster.Region().ID()
	internalID := cluster.ID()

	tempClient, err := c.AssumeRole(ccsJumpRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("2 failed to assume into jump-role: %w", err)
	}

	jumpRoleClient, err := tempClient.AssumeRole(supportRole, region)
	if err != nil {
		return aws.Client{}, fmt.Errorf("3 failed to assume into jump-role: %w", err)
	}
	customerRole, err := c.GetSupportRoleARN(internalID)
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
