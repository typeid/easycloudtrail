package aws

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi/resourcegroupstaggingapiiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

var (
	DefaultRegion = "us-east-1"
)

// Client is a representation of the AWS Client.
type Client struct {
	Region           string
	StsClient        stsiface.STSAPI
	CloudTrailClient cloudtrailiface.CloudTrailAPI
	ResourceGroupAPI resourcegroupstaggingapiiface.ResourceGroupsTaggingAPIAPI
}

func GetAWSClient(awsRegion string) (*Client, error) {
	return GetAWSClientWithRegion(awsRegion)
}

func GetAWSClientWithRegion(awsRegion string) (*Client, error) {
	if awsRegion == "" {
		var hasAwsDefaultRegion bool
		awsRegion, hasAwsDefaultRegion = os.LookupEnv("AWS_DEFAULT_REGION")
		if !hasAwsDefaultRegion {
			awsRegion = DefaultRegion
		}
	}

	session, err := session.NewSessionWithOptions(
		session.Options{Config: aws.Config{Region: aws.String(awsRegion)}},
	)
	if err != nil {
		return nil, err
	}

	return &Client{
		Region:           *aws.String(awsRegion),
		CloudTrailClient: cloudtrail.New(session),
		StsClient:        sts.New(session),
		ResourceGroupAPI: resourcegroupstaggingapi.New(session),
	}, nil
}
