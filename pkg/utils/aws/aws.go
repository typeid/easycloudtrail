package aws

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

const (
	maxRetries        int = 3
	backoffUpperLimit     = 5 * time.Minute
)

// Client is a representation of the AWS Client
type Client struct {
	Region           string
	StsClient        stsiface.STSAPI
	CloudTrailClient cloudtrailiface.CloudTrailAPI
}

// newClient creates a new client and is used when we already know the secrets and region,
// without any need to do any lookup.
func newClient(accessID, accessSecret, token, region string) (Client, error) {
	awsConfig := &aws.Config{
		Region:                        aws.String(region),
		Credentials:                   credentials.NewStaticCredentials(accessID, accessSecret, token),
		CredentialsChainVerboseErrors: aws.Bool(true),
		Retryer: client.DefaultRetryer{
			NumMaxRetries:    maxRetries,
			MinThrottleDelay: 2 * time.Second,
		},
	}

	s, err := session.NewSession(awsConfig)
	if err != nil {
		return Client{}, err
	}

	cloudTrailSess, err := session.NewSession(awsConfig)
	if err != nil {
		return Client{}, err
	}

	return Client{
		Region:           *aws.String(region),
		StsClient:        sts.New(s),
		CloudTrailClient: cloudtrail.New(cloudTrailSess),
	}, nil
}

// AssumeRole returns you a new client in the account specified in the roleARN
func (c *Client) AssumeRole(roleARN, region string) (Client, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         &roleARN,
		RoleSessionName: aws.String("srep-cloudtrail-check"),
	}
	out, err := c.StsClient.AssumeRole(input)
	if err != nil {
		return Client{}, err
	}
	if region == "" {
		region = c.Region
	}
	return newClient(*out.Credentials.AccessKeyId,
		*out.Credentials.SecretAccessKey,
		*out.Credentials.SessionToken,
		region)
}

// containsEvent is a little helper function that checks if the list contains an event
func containsEvent(e *cloudtrail.Event, events []*cloudtrail.Event) bool {
	for _, event := range events {
		if event == e {
			return true
		}
	}
	return false
}

func GetAWSClient() (Client, error) {
	return GetAWSClientWithRegion("")
}

func GetAWSClientWithRegion(awsRegion string) (Client, error) {

	if awsRegion == "" {
		var hasAwsDefaultRegion bool
		awsRegion, hasAwsDefaultRegion = os.LookupEnv("AWS_DEFAULT_REGION")
		if !hasAwsDefaultRegion {
			awsRegion = "us-east-1"
		}
	}

	sess, err := session.NewSession(&aws.Config{Region: aws.String(awsRegion)})
	if err != nil {
		return Client{}, err
	}

	return Client{
		Region:           *aws.String(awsRegion),
		CloudTrailClient: cloudtrail.New(sess),
	}, nil
}

func (c *Client) GetCloudTrailEvents(startTime time.Time) {
	input := &cloudtrail.LookupEventsInput{StartTime: aws.Time(startTime), EndTime: aws.Time(time.Now()), LookupAttributes: []*cloudtrail.LookupAttribute{{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")}}}
	resp, err := c.CloudTrailClient.LookupEvents(input)
	if err != nil {
		fmt.Println("Got error calling CreateTrail:")
		fmt.Println(err.Error())
		return
	}

	for _, event := range resp.Events {
		if aws.StringValue(event.Username) != "test" { //not in whitelist
			// fmt.Println("Event:")
			// fmt.Println(aws.StringValue(event.CloudTrailEvent))
			fmt.Println(aws.StringValue(event.EventName), "| ", aws.TimeValue(event.EventTime), "| User:", aws.StringValue(event.Username))

			// fmt.Println("Resources:")

			// for _, resource := range event.Resources {
			// 	fmt.Println("  Name:", aws.StringValue(resource.ResourceName))
			// 	fmt.Println("  Type:", aws.StringValue(resource.ResourceType))
			// }
		}
	}

}
