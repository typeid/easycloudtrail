package aws

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/cloudtrail/cloudtrailiface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

// Client is a representation of the AWS Client
type Client struct {
	Region           string
	StsClient        stsiface.STSAPI
	CloudTrailClient cloudtrailiface.CloudTrailAPI
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

func GetAWSClient(awsRegion string) (*Client, error) {
	return GetAWSClientWithRegion(awsRegion)
}

func GetAWSClientWithRegion(awsRegion string) (*Client, error) {
	if awsRegion == "" {
		var hasAwsDefaultRegion bool
		awsRegion, hasAwsDefaultRegion = os.LookupEnv("AWS_DEFAULT_REGION")
		if !hasAwsDefaultRegion {
			awsRegion = "us-east-1"
		}
	}

	cloudTrailSession, err := session.NewSessionWithOptions(session.Options{Config: aws.Config{Region: aws.String(awsRegion)}})
	if err != nil {
		return nil, err
	}

	stsSession, err := session.NewSessionWithOptions(session.Options{Config: aws.Config{Region: aws.String(awsRegion)}})
	if err != nil {
		return nil, err
	}

	return &Client{
		Region:           *aws.String(awsRegion),
		CloudTrailClient: cloudtrail.New(cloudTrailSession),
		StsClient:        sts.New(stsSession),
	}, nil
}

func matchesRegexpList(value string, regexpList []string) (bool, error) {
	for _, regexpI := range regexpList {
		matched, err := regexp.MatchString(regexpI, value)
		if err != nil {
			return false, err
		}

		if matched {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) GetCloudTrailEvents(startTime time.Time, raw bool, whitelistedUsers []string) error {
	input := &cloudtrail.LookupEventsInput{StartTime: aws.Time(startTime), EndTime: aws.Time(time.Now()), LookupAttributes: []*cloudtrail.LookupAttribute{{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")}}}
	resp, err := c.CloudTrailClient.LookupEvents(input)
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		whitelistMatched, err := matchesRegexpList(aws.StringValue(event.Username), whitelistedUsers)
		if err != nil {
			return err
		}

		if !whitelistMatched { // Event not in whitelist
			if !raw {
				fmt.Println(aws.StringValue(event.EventName), "| ", aws.TimeValue(event.EventTime), "| User:", aws.StringValue(event.Username))
			} else {
				fmt.Println("")
				fmt.Println(aws.StringValue(event.CloudTrailEvent))
			}
		}
	}
	return nil
}
