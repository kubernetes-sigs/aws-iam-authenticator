package endpoints

import (
	"fmt"
)

// Represents the partitions recognized by the github.com/aws/aws-sdk-go/aws/endpoints
// package. Obtaining these partitions has been deprecated in the AWS SDK Go V2, so this serves as a
// hardcoded alternative. Source: https://github.com/aws/aws-sdk-go/blob/main/aws/endpoints/defaults.go
const (
	AwsPartitionID      = "aws"        // AWS Standard partition.
	AwsCnPartitionID    = "aws-cn"     // AWS China partition.
	AwsUsGovPartitionID = "aws-us-gov" // AWS GovCloud (US) partition.
	AwsIsoPartitionID   = "aws-iso"    // AWS ISO (US) partition.
	AwsIsoBPartitionID  = "aws-iso-b"  // AWS ISOB (US) partition.
	AwsIsoEPartitionID  = "aws-iso-e"  // AWS ISOE (Europe) partition.
	AwsIsoFPartitionID  = "aws-iso-f"  // AWS ISOF partition.
	AwsEuscPartitionID  = "aws-eusc"   // AWS EUSC (Europe) partition."
)

var (
	PARTITIONS = []string{
		AwsPartitionID,
		AwsCnPartitionID,
		AwsUsGovPartitionID,
		AwsIsoPartitionID,
		AwsIsoBPartitionID,
		AwsIsoEPartitionID,
		AwsIsoFPartitionID,
		AwsEuscPartitionID,
	}
)

// Returns the STS domain for the given partition. Returns an error
// if the partition is not recognized.
func GetSTSPartitionDomain(partition string) (string, error) {
	var domain string

	switch partition {
	case AwsPartitionID:
		domain = "amazonaws.com"
	case AwsCnPartitionID:
		domain = "amazonaws.com.cn"
	case AwsUsGovPartitionID:
		domain = "amazonaws.com"
	case AwsIsoPartitionID:
		domain = "c2s.ic.gov"
	case AwsIsoBPartitionID:
		domain = "sc2s.sgov.gov"
	case AwsIsoEPartitionID:
		domain = "cloud.adc-e.uk"
	case AwsIsoFPartitionID:
		domain = "csp.hci.ic.gov"
	case AwsEuscPartitionID:
		domain = "amazonaws.eu"
	default:
		return "", fmt.Errorf("partition %s not valid", partition)
	}

	return domain, nil
}

// Gets the dual stack domain for the given partition. Returns an empty string
// if the partition does not support dual stack
// To determine if a partition supports dual stack, check in the SDK
// https://github.com/aws/aws-sdk-go-v2/blob/f68827f17283ffb439c64aa951a6dd4852bef8e2/internal/endpoints/awsrulesfn/partitions.json
func GetSTSDualStackPartitionDomain(partition string) string {
	var domain string

	switch partition {
	case AwsPartitionID:
		domain = "api.aws"
	case AwsUsGovPartitionID:
		domain = "api.aws"
	case AwsCnPartitionID:
		domain = "api.amazonwebservices.com.cn"
	case AwsEuscPartitionID:
		domain = "api.amazonwebservices.eu"
	default:
		return ""
	}

	return domain
}
