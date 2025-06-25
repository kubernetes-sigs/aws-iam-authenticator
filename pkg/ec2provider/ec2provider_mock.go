package ec2provider

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type MockEc2Client struct {
	Reservations []*ec2types.Reservation
	Regions      []ec2types.Region
}

const (
	DescribeDelay = 100
)

func newMockedEC2ProviderImpl() *ec2ProviderImpl {
	dnsCache := ec2PrivateDNSCache{
		cache: make(map[string]string),
		lock:  sync.RWMutex{},
	}
	ec2Requests := ec2Requests{
		set:  make(map[string]bool),
		lock: sync.RWMutex{},
	}
	return &ec2ProviderImpl{
		ec2:                &MockEc2Client{},
		privateDNSCache:    dnsCache,
		ec2Requests:        ec2Requests,
		instanceIdsChannel: make(chan string, maxChannelSize),
	}

}

func (c *MockEc2Client) DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	// simulate the time it takes for aws to return
	time.Sleep(DescribeDelay * time.Millisecond)
	var reservations []ec2types.Reservation
	for _, res := range c.Reservations {
		var reservation ec2types.Reservation
		for _, inst := range res.Instances {
			for _, id := range in.InstanceIds {
				if id == aws.ToString(inst.InstanceId) {
					reservation.Instances = append(reservation.Instances, inst)
				}
			}
		}
		if len(reservation.Instances) > 0 {
			reservations = append(reservations, reservation)
		}
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: reservations,
	}, nil
}

func (c *MockEc2Client) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if c.Regions == nil {
		return &ec2.DescribeRegionsOutput{}, nil
	}
	return &ec2.DescribeRegionsOutput{Regions: c.Regions}, nil
}
