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

func (c *Client) PrintCloudTrailWriteEvents(
	startTime time.Time,
	raw bool,
	ignoredUsers []string,
	toggleEventID bool,
	tag *ResourceTag,
) error {
	if tag == nil {
		lookupInput := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(startTime),
			EndTime:   aws.Time(time.Now()),
			LookupAttributes: []*cloudtrail.LookupAttribute{
				{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")},
			},
		}

		return c.printCloudTrailEvents(
			startTime,
			raw,
			ignoredUsers,
			toggleEventID,
			lookupInput,
			func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool {
				// Add write-only filtering condition
				return rawEvent.UserIdentity.Type != "AWSService"
			},
		)
	}

	// Lookup and print only tagged resource events
	resourceARNs, err := c.getTaggedResources(*tag)
	if err != nil {
		return err
	}

	for _, resource := range resourceARNs {
		resourceCopy := resource // Fixes G601
		lookupInput := &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(startTime),
			EndTime:   aws.Time(time.Now()),
			LookupAttributes: []*cloudtrail.LookupAttribute{
				{AttributeKey: aws.String("ResourceName"), AttributeValue: &resourceCopy.Name},
				{AttributeKey: aws.String("ReadOnly"), AttributeValue: aws.String("false")},
			},
		}

		err := c.printCloudTrailEvents(
			startTime,
			raw,
			ignoredUsers,
			toggleEventID,
			lookupInput,
			func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool {
				return rawEvent.UserIdentity.Type != "AWSService"
			},
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) PrintCloudTrailForbiddenEvents(
	startTime time.Time,
	raw bool,
	ignoredUsers []string,
	toggleEventID bool,
) error {
	return c.printCloudTrailEvents(
		startTime,
		raw,
		ignoredUsers,
		toggleEventID,
		nil,
		func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool {
			return hasUnauthorizedResponse(*event.CloudTrailEvent)
		},
	)
}

func (c *Client) printCloudTrailEvents( //nolint:gocognit
	startTime time.Time,
	raw bool,
	ignoredUsers []string,
	toggleEventID bool,
	lookupInput *cloudtrail.LookupEventsInput,
	postLookupFilterFunc func(event *cloudtrail.Event, sessionIssuerUsername string, rawEvent *CloudTrailEventRaw) bool,
) error {
	if lookupInput == nil {
		// Default to querying everything
		lookupInput = &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(startTime),
			EndTime:   aws.Time(time.Now()),
		}
	}

	allEvents := []*cloudtrail.Event{}

	for {
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

		ignoredUserMatched, err := utils.MatchesRegexpList(
			aws.StringValue(event.Username),
			ignoredUsers,
		)
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
				err := printEventNonRaw(event, sessionIssuerUsername, toggleEventID)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func hasUnauthorizedResponse(eventMessage string) bool {
	return strings.Contains(eventMessage, "\"errorCode\":\"Client.UnauthorizedOperation\"")
}

func printEventNonRaw(
	event *cloudtrail.Event,
	sessionIssuerUsername string,
	toggleEventID bool,
) error {
	if sessionIssuerUsername == "" && aws.StringValue(event.Username) == "" {
		// Avoid printing "system" events with no user assigned to the action
		return nil
	}

	accumulatingString := ""
	accumulatingString += aws.StringValue(event.EventName)
	accumulatingString += fmt.Sprintf(" | %s", aws.TimeValue(event.EventTime))

	if event.Username != nil {
		accumulatingString += fmt.Sprintf(" | User: %s", aws.StringValue(event.Username))
	}

	if sessionIssuerUsername != "" {
		accumulatingString += fmt.Sprintf(" | ARN: %s", sessionIssuerUsername)
	}

	if toggleEventID {
		accumulatingString += fmt.Sprintf(" | EventID: %s", aws.StringValue(event.EventId))
	}

	fmt.Println(accumulatingString)

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
