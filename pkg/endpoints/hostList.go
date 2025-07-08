package endpoints

// Represents the partitions and STS hosts recognized by the github.com/aws/aws-sdk-go/aws/endpoints
// package. Obtaining these endpoints has been deprecated in the AWS SDK Go V2, so this serves as a
// hardcoded alternative. Source: https://github.com/aws/aws-sdk-go/blob/main/aws/endpoints/defaults.go
const (
	AwsPartitionID      = "aws"        // AWS Standard partition.
	AwsCnPartitionID    = "aws-cn"     // AWS China partition.
	AwsUsGovPartitionID = "aws-us-gov" // AWS GovCloud (US) partition.
	AwsIsoPartitionID   = "aws-iso"    // AWS ISO (US) partition.
	AwsIsoBPartitionID  = "aws-iso-b"  // AWS ISOB (US) partition.
	AwsIsoEPartitionID  = "aws-iso-e"  // AWS ISOE (Europe) partition.
	AwsIsoFPartitionID  = "aws-iso-f"  // AWS ISOF partition.
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
	}

	AWS_PARTITION_STS_HOSTS = []string{
		"sts.amazonaws.com",
		"sts-fips.us-east-1.amazonaws.com",
		"sts-fips.us-east-2.amazonaws.com",
		"sts-fips.us-west-1.amazonaws.com",
		"sts-fips.us-west-2.amazonaws.com",
		"sts.af-south-1.amazonaws.com",
		"sts.ap-east-1.amazonaws.com",
		"sts.ap-northeast-1.amazonaws.com",
		"sts.ap-northeast-2.amazonaws.com",
		"sts.ap-northeast-3.amazonaws.com",
		"sts.ap-south-1.amazonaws.com",
		"sts.ap-south-2.amazonaws.com",
		"sts.ap-southeast-1.amazonaws.com",
		"sts.ap-southeast-2.amazonaws.com",
		"sts.ap-southeast-3.amazonaws.com",
		"sts.ap-southeast-4.amazonaws.com",
		"sts.ca-central-1.amazonaws.com",
		"sts.ca-west-1.amazonaws.com",
		"sts.eu-central-1.amazonaws.com",
		"sts.eu-central-2.amazonaws.com",
		"sts.eu-north-1.amazonaws.com",
		"sts.eu-south-1.amazonaws.com",
		"sts.eu-south-2.amazonaws.com",
		"sts.eu-west-1.amazonaws.com",
		"sts.eu-west-2.amazonaws.com",
		"sts.eu-west-3.amazonaws.com",
		"sts.il-central-1.amazonaws.com",
		"sts.me-central-1.amazonaws.com",
		"sts.me-south-1.amazonaws.com",
		"sts.sa-east-1.amazonaws.com",
		"sts.us-east-1.amazonaws.com",
		"sts.us-east-2.amazonaws.com",
		"sts.us-west-1.amazonaws.com",
		"sts.us-west-2.amazonaws.com",
	}

	AWS_CN_STS_HOSTS = []string{
		"sts.cn-north-1.amazonaws.com.cn",
		"sts.cn-northwest-1.amazonaws.com.cn",
	}

	US_GOV_STS_HOSTS = []string{
		"sts.us-gov-east-1.amazonaws.com",
		"sts.us-gov-west-1.amazonaws.com",
	}

	US_ISO_STS_HOSTS = []string{
		"sts.us-iso-east-1.c2s.ic.gov",
		"sts.us-iso-west-1.c2s.ic.gov",
	}

	US_ISO_B_HOSTS = []string{
		"sts.us-isob-east-1.sc2s.sgov.gov",
	}

	US_ISO_E_HOSTS = []string{}

	US_ISO_F_HOSTS = []string{}
)

func GetSTSEndpoints(partition string) []string {
	switch partition {
	case AwsPartitionID:
		return AWS_PARTITION_STS_HOSTS
	case AwsCnPartitionID:
		return AWS_CN_STS_HOSTS
	case AwsUsGovPartitionID:
		return US_GOV_STS_HOSTS
	case AwsIsoPartitionID:
		return US_ISO_STS_HOSTS
	case AwsIsoBPartitionID:
		return US_ISO_B_HOSTS
	case AwsIsoEPartitionID:
		return US_ISO_E_HOSTS
	case AwsIsoFPartitionID:
		return US_ISO_F_HOSTS
	default:
		return []string{}
	}
}
