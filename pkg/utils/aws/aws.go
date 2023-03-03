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
	_ "github.com/golang/mock/mockgen/model" //revive:disable:blank-imports used for the mockgen generation
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

// NewClient creates a new client and is used when we already know the secrets and region,
// without any need to do any lookup.
func NewClient(accessID, accessSecret, token, region string) (Client, error) {
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
	return NewClient(*out.Credentials.AccessKeyId,
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

// GetAWSClient will retrieve the AwsClient from the 'aws' package
func GetAWSClient() (Client, error) {
	awsAccessKeyID, hasAwsAccessKeyID := os.LookupEnv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey, hasAwsSecretAccessKey := os.LookupEnv("AWS_SECRET_ACCESS_KEY")
	awsSessionToken, hasAwsSessionToken := os.LookupEnv("AWS_SESSION_TOKEN")
	awsDefaultRegion, hasAwsDefaultRegion := os.LookupEnv("AWS_DEFAULT_REGION")
	if !hasAwsAccessKeyID || !hasAwsSecretAccessKey {
		return Client{}, fmt.Errorf("one of the required envvars in the list '(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)' is missing")
	}
	if !hasAwsSessionToken {
		fmt.Println("AWS_SESSION_TOKEN not provided, but is not required ")
	}
	if !hasAwsDefaultRegion {
		awsDefaultRegion = "us-east-1"
	}

	return NewClient(awsAccessKeyID, awsSecretAccessKey, awsSessionToken, awsDefaultRegion)
}

func (c *Client) GetCloudTrailEvents() {
	input := &cloudtrail.LookupEventsInput{EndTime: aws.Time(time.Now()), LookupAttributes: []*cloudtrail.LookupAttribute{{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")}}}
	resp, err := c.CloudTrailClient.LookupEvents(input)
	if err != nil {
		fmt.Println("Got error calling CreateTrail:")
		fmt.Println(err.Error())
		return
	}

	for _, event := range resp.Events {
		if aws.StringValue(event.Username) != "root" { //not in whitelist
			// fmt.Println("Event:")
			// fmt.Println(aws.StringValue(event.CloudTrailEvent))
			fmt.Println("")
			fmt.Println("Name    ", aws.StringValue(event.EventName))
			fmt.Println("ID:     ", aws.StringValue(event.EventId))
			fmt.Println("Time:   ", aws.TimeValue(event.EventTime))
			fmt.Println("User:   ", aws.StringValue(event.Username))

			fmt.Println("Resources:")

			for _, resource := range event.Resources {
				fmt.Println("  Name:", aws.StringValue(resource.ResourceName))
				fmt.Println("  Type:", aws.StringValue(resource.ResourceType))
			}

			fmt.Println("")
		}
	}
}
