package aws

import (
	"easycloudtrail/pkg/utils"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"golang.org/x/exp/slices"
)

func (c *Client) PrintCloudTrailWriteEvents(startTime time.Time, raw bool, ignoredUsers []string) error {

	lookupInput := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(startTime),
		EndTime:   aws.Time(time.Now()),
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")},
		},
	}

	return c.printCloudTrailEvents(startTime, raw, ignoredUsers, lookupInput, func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool {
		// Add write-only filtering condition
		return rawEvent.UserIdentity.Type != "AWSService"
	})
}

func (c *Client) PrintCloudTrailForbiddenEvents(startTime time.Time, raw bool, ignoredUsers []string) error {
	return c.printCloudTrailEvents(startTime, raw, ignoredUsers, nil, func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool {
		return hasUnauthorizedResponse(*event.CloudTrailEvent)
	})
}

func (c *Client) printCloudTrailEvents(startTime time.Time, raw bool, ignoredUsers []string, lookupInput *cloudtrail.LookupEventsInput, postLookupFilterFunc func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool) error {

	if lookupInput == nil {
		// Default to querying everything
		lookupInput = &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(startTime),
			EndTime:   aws.Time(time.Now()),
		}

	}

	allEvents := []*cloudtrail.Event{}

	for {
		print(".")
		lookupOutput, err := c.CloudTrailClient.LookupEvents(lookupInput)
		if err != nil {
			return err
		}

		allEvents = append(allEvents, lookupOutput.Events...)

		if lookupOutput.NextToken == nil {
			break
		}

		lookupInput.NextToken = lookupOutput.NextToken
	}
	print("\n")

	// Reverse order to have newest events printed last
	utils.ReverseSlice(allEvents)

	for _, event := range allEvents {
		userDetails, err := extractUserDetails(event.CloudTrailEvent)
		if err != nil {
			return err
		}
		sessionIssuerUsername := userDetails.UserIdentity.SessionContext.SessionIssuer.UserName

		ignoredARNMatched, err := utils.MatchesRegexpList(sessionIssuerUsername, ignoredUsers)
		if err != nil {
			return err
		}

		ignoredUserMatched, err := utils.MatchesRegexpList(aws.StringValue(event.Username), ignoredUsers)
		if err != nil {
			return err
		}

		if ignoredUserMatched || ignoredARNMatched {
			// Skip entry
			continue
		}

		filtered := postLookupFilterFunc(event, sessionIssuerUsername, userDetails)

		if filtered {
			if raw {
				fmt.Printf("\n")
				fmt.Println(aws.StringValue(event.CloudTrailEvent))
			} else {
				printEventNonRaw(event, sessionIssuerUsername)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func hasUnauthorizedResponse(eventMessage string) bool {
	return strings.Contains(eventMessage, "\"errorCode\": \"Client.UnauthorizedOperation\"")
}

func printEventNonRaw(event *cloudtrail.Event, sessionIssuerUsername string) error {

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

func extractUserDetails(cloudTrailEvent *string) (*CloudTrailEventRaw, error) {
	if cloudTrailEvent == nil || *cloudTrailEvent == "" {
		return &CloudTrailEventRaw{}, fmt.Errorf("cannot parse a nil input")
	}
	var res CloudTrailEventRaw
	err := json.Unmarshal([]byte(*cloudTrailEvent), &res)
	if err != nil {
		return &CloudTrailEventRaw{}, fmt.Errorf("could not marshal event.CloudTrailEvent: %w", err)
	}
	supportedEventVersions := []string{"1.08", "1.09"}
	if !slices.Contains(supportedEventVersions, res.EventVersion) {
		return &CloudTrailEventRaw{},
			fmt.Errorf("cloudtrail event version '%s' is not yet supported by cloudtrailctl",
				res.EventVersion)
	}
	return &res, nil
}
