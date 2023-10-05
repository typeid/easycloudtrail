package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi"
)

type ResourceTag struct {
	Key   string
	Value string
}

type Resource struct {
	ARN  string
	Name string
	Type string
}

func extractResourceDataFromARN(arn string) (Resource, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 1 {
		return Resource{}, fmt.Errorf("unable to extract resource type/name from ARN: '%s'", arn)
	}
	resourceTypeAndName := parts[len(parts)-1]
	// resourceTypeAndName can have the following format:
	// - instance/i-026ed0789c236cbbd
	// - targetgroup/hs-mc12341312/412c1df5604d9
	// - bucketname coming from arn:aws:s3:::bucketname
	// For the latter type, AWS is inconsistent and uses the whole ARN as resource name,
	// so we just return the ARN in that case

	resourceName := strings.Split(resourceTypeAndName, "/")

	// E.g. s3 buckets, initially arn:aws:s3:::bucketname
	// after the first split, it's just the bucketname
	if len(resourceName) == 1 {
		return Resource{ARN: arn, Name: resourceName[0], Type: "unknown"}, nil
	}
	// E.g oldschool load balancers where the name of the resource is the whole ARN
	// After splitting with `:`, the resourceName for those is e.g. targetgroup/hs-mc12341312/412c1df5604d9
	if len(resourceName) > 2 { //nolint:gomnd // non-standard format
		return Resource{ARN: arn, Name: arn, Type: resourceName[0]}, nil
	}

	return Resource{ARN: arn, Name: resourceName[len(resourceName)-1], Type: resourceName[0]}, nil
}

func (c *Client) getTaggedResources(t ResourceTag) ([]Resource, error) {
	maxFetch := 100
	filter := &resourcegroupstaggingapi.TagFilter{Key: &t.Key, Values: []*string{&t.Value}}
	input := &resourcegroupstaggingapi.GetResourcesInput{
		TagFilters:       []*resourcegroupstaggingapi.TagFilter{filter},
		ResourcesPerPage: aws.Int64(int64(maxFetch)),
	}
	output, err := c.ResourceGroupAPI.GetResources(input)
	if err != nil {
		return nil, fmt.Errorf("could not get tagged resources: %w", err)
	}

	var taggedResources []Resource
	for _, resourcesMappings := range output.ResourceTagMappingList {
		resource, err := extractResourceDataFromARN(*resourcesMappings.ResourceARN)
		if err != nil {
			fmt.Println(err)
			continue
		}

		taggedResources = append(taggedResources, resource)
	}

	return taggedResources, nil
}
