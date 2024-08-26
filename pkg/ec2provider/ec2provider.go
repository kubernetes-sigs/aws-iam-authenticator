package ec2provider

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg"
	"sigs.k8s.io/aws-iam-authenticator/pkg/httputil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

const (
	// max limit of k8s nodes support
	maxChannelSize = 8000
	// max number of in flight non batched ec2:DescribeInstances request to flow
	maxAllowedInflightRequest = 5
	// default wait interval for the ec2 instance id request which is already in flight
	defaultWaitInterval = 50 * time.Millisecond
	// Making sure the single instance calls waits max till 5 seconds 100* (50 * time.Millisecond)
	totalIterationForWaitInterval = 100
	// Maximum number of instances with which ec2:DescribeInstances call will be made
	maxInstancesBatchSize = 100
	// Maximum time in Milliseconds to wait for a new batch call this also depends on if the instance size has
	// already become 100 then it will not respect this limit
	maxWaitIntervalForBatch = 200

	// Headers for STS request for source ARN
	headerSourceArn = "x-amz-source-arn"
	// Headers for STS request for source account
	headerSourceAccount = "x-amz-source-account"
)

// Get a node name from instance ID
type EC2Provider interface {
	GetPrivateDNSName(string) (string, error)
	StartEc2DescribeBatchProcessing()
}

type ec2PrivateDNSCache struct {
	cache map[string]string
	lock  sync.RWMutex
}

type ec2Requests struct {
	set  map[string]bool
	lock sync.RWMutex
}

type ec2ProviderImpl struct {
	ec2                ec2iface.EC2API
	privateDNSCache    ec2PrivateDNSCache
	ec2Requests        ec2Requests
	instanceIdsChannel chan string
}

func New(roleARN, sourceARN, region string, qps int, burst int) EC2Provider {
	dnsCache := ec2PrivateDNSCache{
		cache: make(map[string]string),
		lock:  sync.RWMutex{},
	}
	ec2Requests := ec2Requests{
		set:  make(map[string]bool),
		lock: sync.RWMutex{},
	}
	return &ec2ProviderImpl{
		ec2:                ec2.New(newSession(roleARN, sourceARN, region, qps, burst)),
		privateDNSCache:    dnsCache,
		ec2Requests:        ec2Requests,
		instanceIdsChannel: make(chan string, maxChannelSize),
	}
}

// Initial credentials loaded from SDK's default credential chain, such as
// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
// Role.

func newSession(roleARN, sourceARN, region string, qps int, burst int) *session.Session {
	sess := session.Must(session.NewSession())
	sess.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "authenticatorUserAgent",
		Fn: request.MakeAddToUserAgentHandler(
			"aws-iam-authenticator", pkg.Version),
	})
	if aws.StringValue(sess.Config.Region) == "" {
		sess.Config.Region = aws.String(region)
	}

	if roleARN != "" {
		logrus.WithFields(logrus.Fields{
			"roleARN": roleARN,
		}).Infof("Using assumed role for EC2 API")

		rateLimitedClient, err := httputil.NewRateLimitedClient(qps, burst)

		if err != nil {
			logrus.Errorf("Getting error = %s while creating rate limited client ", err)
		}

		stsClient := applySTSRequestHeaders(sts.New(sess, aws.NewConfig().WithHTTPClient(rateLimitedClient).WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)), sourceARN)
		ap := &stscreds.AssumeRoleProvider{
			Client:   stsClient,
			RoleARN:  roleARN,
			Duration: time.Duration(60) * time.Minute,
		}

		sess.Config.Credentials = credentials.NewCredentials(ap)
	}
	return sess
}

func (p *ec2ProviderImpl) setPrivateDNSNameCache(id string, privateDNSName string) {
	p.privateDNSCache.lock.Lock()
	defer p.privateDNSCache.lock.Unlock()
	p.privateDNSCache.cache[id] = privateDNSName
}

func (p *ec2ProviderImpl) setRequestInFlightForInstanceId(id string) {
	p.ec2Requests.lock.Lock()
	defer p.ec2Requests.lock.Unlock()
	p.ec2Requests.set[id] = true
}

func (p *ec2ProviderImpl) unsetRequestInFlightForInstanceId(id string) {
	p.ec2Requests.lock.Lock()
	defer p.ec2Requests.lock.Unlock()
	delete(p.ec2Requests.set, id)
}

func (p *ec2ProviderImpl) getRequestInFlightForInstanceId(id string) bool {
	p.ec2Requests.lock.RLock()
	defer p.ec2Requests.lock.RUnlock()
	_, ok := p.ec2Requests.set[id]
	return ok
}

func (p *ec2ProviderImpl) getRequestInFlightSize() int {
	p.ec2Requests.lock.RLock()
	defer p.ec2Requests.lock.RUnlock()
	length := len(p.ec2Requests.set)
	return length
}

// GetPrivateDNS looks up the private DNS from the EC2 API
func (p *ec2ProviderImpl) getPrivateDNSNameCache(id string) (string, error) {
	p.privateDNSCache.lock.RLock()
	defer p.privateDNSCache.lock.RUnlock()
	name, ok := p.privateDNSCache.cache[id]
	if ok {
		return name, nil
	}
	return "", errors.New("instance id not found")
}

// Only calls API if its not in the cache
func (p *ec2ProviderImpl) GetPrivateDNSName(id string) (string, error) {
	privateDNSName, err := p.getPrivateDNSNameCache(id)
	if err == nil {
		return privateDNSName, nil
	}
	logrus.Debugf("Missed the cache for the InstanceId = %s Verifying if its already in requestQueue ", id)
	// check if the request for instanceId already in queue.
	if p.getRequestInFlightForInstanceId(id) {
		logrus.Debugf("Found the InstanceId:= %s request In Queue waiting in 5 seconds loop ", id)
		for i := 0; i < totalIterationForWaitInterval; i++ {
			time.Sleep(defaultWaitInterval)
			privateDNSName, err := p.getPrivateDNSNameCache(id)
			if err == nil {
				return privateDNSName, nil
			}
		}
		return "", fmt.Errorf("failed to find node %s in PrivateDNSNameCache returning from loop", id)
	}
	logrus.Debugf("Missed the requestQueue cache for the InstanceId = %s", id)
	p.setRequestInFlightForInstanceId(id)
	requestQueueLength := p.getRequestInFlightSize()
	//The code verifies if the requestQuqueMap size is greater than max request in flight with rate
	//limiting then writes to the channel where we are making batch ec2:DescribeInstances API call.
	if requestQueueLength > maxAllowedInflightRequest {
		logrus.Debugf("Writing to buffered channel for instance Id %s ", id)
		p.instanceIdsChannel <- id
		return p.GetPrivateDNSName(id)
	}

	logrus.Infof("Calling ec2:DescribeInstances for the InstanceId = %s ", id)
	metrics.Get().EC2DescribeInstanceCallCount.Inc()
	// Look up instance from EC2 API
	output, err := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{id}),
	})
	if err != nil {
		p.unsetRequestInFlightForInstanceId(id)
		return "", fmt.Errorf("failed querying private DNS from EC2 API for node %s: %s ", id, err.Error())
	}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				privateDNSName = aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSNameCache(id, privateDNSName)
				p.unsetRequestInFlightForInstanceId(id)
			}
		}
	}

	if privateDNSName == "" {
		return "", fmt.Errorf("failed to find node %s ", id)
	}
	return privateDNSName, nil
}

func (p *ec2ProviderImpl) StartEc2DescribeBatchProcessing() {
	startTime := time.Now()
	var instanceIdList []string
	for {
		var instanceId string
		select {
		case instanceId = <-p.instanceIdsChannel:
			logrus.Debugf("Received the Instance Id := %s from buffered Channel for batch processing ", instanceId)
			instanceIdList = append(instanceIdList, instanceId)
		default:
			// Waiting for more elements to get added to the buffered Channel
			// And to support the for select loop.
			time.Sleep(20 * time.Millisecond)
		}
		endTime := time.Now()
		/*
			The if statement checks for empty list and ignores to make any ec2:Describe API call
			If elements are less than 100 and time of 200 millisecond has elapsed it will make the
			ec2:DescribeInstances call with as many elements in the list.
			It is also possible that if the system gets more than 99 elements in the list in less than
			200 milliseconds time it will the ec2:DescribeInstances call and that's our whole point of
			optimization here. Also for FYI we have client level rate limiting which is what this
			ec2:DescribeInstances call will make so this call is also rate limited.
		*/
		if (len(instanceIdList) > 0 && (endTime.Sub(startTime).Milliseconds()) > maxWaitIntervalForBatch) || len(instanceIdList) > maxInstancesBatchSize {
			startTime = time.Now()
			dupInstanceList := make([]string, len(instanceIdList))
			copy(dupInstanceList, instanceIdList)
			go p.getPrivateDnsAndPublishToCache(dupInstanceList)
			instanceIdList = nil
		}
	}
}

func (p *ec2ProviderImpl) getPrivateDnsAndPublishToCache(instanceIdList []string) {
	// Look up instance from EC2 API
	logrus.Infof("Making Batch Query to DescribeInstances for %v instances ", len(instanceIdList))
	metrics.Get().EC2DescribeInstanceCallCount.Inc()
	output, err := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice(instanceIdList),
	})
	if err != nil {
		logrus.Errorf("Batch call failed querying private DNS from EC2 API for nodes [%s] : with error = []%s ", instanceIdList, err.Error())
	} else {
		if output.NextToken != nil {
			logrus.Debugf("Successfully got the batch result , output.NextToken = %s ", *output.NextToken)
		} else {
			logrus.Debugf("Successfully got the batch result , output.NextToken is nil ")
		}
		// Adding the result to privateDNSChache as well as removing from the requestQueueMap.
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				id := aws.StringValue(instance.InstanceId)
				privateDNSName := aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSNameCache(id, privateDNSName)
			}
		}
	}

	logrus.Debugf("Removing instances from request Queue after getting response from Ec2")
	for _, id := range instanceIdList {
		p.unsetRequestInFlightForInstanceId(id)
	}
}

func applySTSRequestHeaders(stsClient *sts.STS, sourceARN string) *sts.STS {
	// parse both source account and source arn from the sourceARN, and add them as headers to the STS client
	if sourceARN != "" {
		sourceAcct, err := getSourceAccount(sourceARN)
		if err != nil {
			panic(fmt.Sprintf("%s is not a valid arn, err: %v", sourceARN, err))
		}
		reqHeaders := map[string]string{
			headerSourceAccount: sourceAcct,
			headerSourceArn:     sourceARN,
		}
		stsClient.Handlers.Sign.PushFront(func(s *request.Request) {
			s.ApplyOptions(request.WithSetRequestHeaders(reqHeaders))
		})
		logrus.Infof("configuring STS client with extra headers, %v", reqHeaders)
	}
	return stsClient
}

// getSourceAccount constructs source acct and return them for use
func getSourceAccount(roleARN string) (string, error) {
	// ARN format (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html)
	// arn:partition:service:region:account-id:resource-type/resource-id
	// IAM format, region is always blank
	// arn:aws:iam::account:role/role-name-with-path
	if !arn.IsARN(roleARN) {
		return "", fmt.Errorf("incorrect ARN format for role %s", roleARN)
	}

	parsedArn, err := arn.Parse(roleARN)
	if err != nil {
		return "", err
	}

	return parsedArn.AccountID, nil
}
