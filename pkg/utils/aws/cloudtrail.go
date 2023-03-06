package aws

import (
	"easycloudtrail/pkg/utils"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

func (c *Client) GetCloudTrailEvents(startTime time.Time, raw bool, ignoredUsers []string) error {
	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(time.Now()),
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")},
		},
	}
	resp, err := c.CloudTrailClient.LookupEvents(input)
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		ignoredUserMatched, err := utils.MatchesRegexpList(aws.StringValue(event.Username), ignoredUsers)
		if err != nil {
			return err
		}
		if ignoredUserMatched {
			// Skip entry
			continue
		}

		if raw {
			fmt.Printf("\n")
			fmt.Println(aws.StringValue(event.CloudTrailEvent))
		} else {
			fmt.Printf(
				"%s | %s | User: %s\n",
				aws.StringValue(event.EventName),
				aws.TimeValue(event.EventTime),
				aws.StringValue(event.Username))
		}
	}
	return nil
}
