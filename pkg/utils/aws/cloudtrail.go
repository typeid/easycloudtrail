package aws

import (
	"easycloudtrail/pkg/utils"
	"encoding/json"
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

	allEvents := []*cloudtrail.Event{}

	for {
		print(".")
		lookupOutput, err := c.CloudTrailClient.LookupEvents(input)
		if err != nil {
			return err
		}

		allEvents = append(allEvents, lookupOutput.Events...)

		if lookupOutput.NextToken == nil {
			break
		}

		input.NextToken = lookupOutput.NextToken
	}
	print("\n")

	for _, event := range allEvents {
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
			printEventNonRaw(event)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func printEventNonRaw(event *cloudtrail.Event) error {
	userDetails, err := extractUserDetails(event.CloudTrailEvent)
	if err != nil {
		return err
	}
	sessionIssuerUsername := userDetails.UserIdentity.SessionContext.SessionIssuer.UserName

	if sessionIssuerUsername == "" {
		fmt.Printf(
			"%s | %s | User: %s\n",
			aws.StringValue(event.EventName),
			aws.TimeValue(event.EventTime),
			aws.StringValue(event.Username))
	} else {
		fmt.Printf(
			"%s | %s | User: %s | ARN: %s \n",
			aws.StringValue(event.EventName),
			aws.TimeValue(event.EventTime),
			aws.StringValue(event.Username),
			sessionIssuerUsername)
	}

	return nil
}

// Type to parse cloudtrail.Event.CloudTrailEvent, which contains the ARN of the session issuer
// This is important in cases the events are "published" with temporary credentials.
type CloudTrailEventRaw struct {
	EventVersion string `json:"eventVersion"`
	UserIdentity struct {
		Type           string `json:"type"`
		SessionContext struct {
			SessionIssuer struct {
				Type     string `json:"type"`
				UserName string `json:"userName"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

func extractUserDetails(cloudTrailEvent *string) (CloudTrailEventRaw, error) {
	if cloudTrailEvent == nil || *cloudTrailEvent == "" {
		return CloudTrailEventRaw{}, fmt.Errorf("cannot parse a nil input")
	}
	var res CloudTrailEventRaw
	err := json.Unmarshal([]byte(*cloudTrailEvent), &res)
	if err != nil {
		return CloudTrailEventRaw{}, fmt.Errorf("could not marshal event.CloudTrailEvent: %w", err)
	}
	const supportedEventVersion = "1.08"
	if res.EventVersion != supportedEventVersion {
		return CloudTrailEventRaw{},
			fmt.Errorf("event version differs from saved one (got %s, want %s) , not sure it's the same schema",
				res.EventVersion, supportedEventVersion)
	}
	return res, nil
}
