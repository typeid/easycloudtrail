package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/resourcegroupstaggingapi"
)

type ResourceTag struct {
	Key   string
	Value string
}

func (c *Client) getTaggedResources(t ResourceTag) ([]string, error) {
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

	var taggedResources []string
	for _, resource := range output.ResourceTagMappingList {
		taggedResources = append(taggedResources, *resource.ResourceARN)
	}

	return taggedResources, nil
}
