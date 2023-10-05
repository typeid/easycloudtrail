package aws

import (
	"testing"
)

func TestExtractResourceNameFromARNStandard(t *testing.T) {
	arn := "arn:aws:ec2:eu-west-1:123456:instance/i-040032f9e766f801f"
	name := "i-040032f9e766f801f"
	resourceType := "instance"

	resourceData, err := extractResourceDataFromARN(arn)
	if err != nil {
		t.Error(err)
	}

	if resourceData.ARN != arn {
		t.Errorf("unexpected arn: %s, expected: %s", resourceData.ARN, arn)
	}

	if resourceData.Name != name {
		t.Errorf("unexpected name: %s, expected: %s", resourceData.Name, name)
	}

	if resourceData.Type != resourceType {
		t.Errorf("unexpected type: %s, expected: %s", resourceData.Type, resourceType)
	}
}

func TestExtractResourceNameFromOldschoolLB(t *testing.T) {
	arn := "arn:aws:elasticloadbalancing:eu-west-1:1234567:loadbalancer/net/typeid-test-int/94029041ad37ac70"
	name := "arn:aws:elasticloadbalancing:eu-west-1:1234567:loadbalancer/net/typeid-test-int/94029041ad37ac70"
	resourceType := "loadbalancer"

	resourceData, err := extractResourceDataFromARN(arn)
	if err != nil {
		t.Error(err)
	}

	if resourceData.ARN != arn {
		t.Errorf("unexpected arn: %s, expected: %s", resourceData.ARN, arn)
	}

	if resourceData.Name != name {
		t.Errorf("unexpected name: %s, expected: %s", resourceData.Name, name)
	}

	if resourceData.Type != resourceType {
		t.Errorf("unexpected type: %s, expected: %s", resourceData.Type, resourceType)
	}
}

func TestExtractResourceNameFromARNs3Bucket(t *testing.T) {
	arn := "arn:aws:s3:::typeid-test-nsqcm-image-registry-eu-west-1-glyaqltfmqmmjlukbxia"
	name := "typeid-test-nsqcm-image-registry-eu-west-1-glyaqltfmqmmjlukbxia"
	resourceType := "unknown"

	resourceData, err := extractResourceDataFromARN(arn)
	if err != nil {
		t.Error(err)
	}

	if resourceData.ARN != arn {
		t.Errorf("unexpected arn: %s, expected: %s", resourceData.ARN, arn)
	}

	if resourceData.Name != name {
		t.Errorf("unexpected name: %s, expected: %s", resourceData.Name, name)
	}

	if resourceData.Type != resourceType {
		t.Errorf("unexpected type: %s, expected: %s", resourceData.Type, resourceType)
	}
}
