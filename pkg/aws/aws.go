/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/sirupsen/logrus"
)

func newSession(roleARN string) *session.Session {
	// Initial credentials loaded from SDK's default credential chain, such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role.

	sess := session.Must(session.NewSession())
	if aws.StringValue(sess.Config.Region) == "" {
		ec2metadata := ec2metadata.New(sess)
		regionFound, err := ec2metadata.Region()
		if err != nil {
			logrus.WithError(err).Fatal("Region not found in shared credentials, environment variable, or instance metadata.")
		}
		sess.Config.Region = aws.String(regionFound)
	}

	if roleARN != "" {
		logrus.WithFields(logrus.Fields{
			"roleARN": roleARN,
		}).Infof("Using assumed role for EC2 API")

		ap := &stscreds.AssumeRoleProvider{
			Client:   sts.New(sess),
			RoleARN:  roleARN,
			Duration: time.Duration(60) * time.Minute,
		}

		sess.Config.Credentials = credentials.NewCredentials(ap)
	}
	return sess
}

type IAMProvider interface {
	// Get a role ARN from role name
	GetRoleArn(string) (string, error)
}

type iamProviderImpl struct {
	sess *session.Session
}

func NewIAMProvider(roleARN string) IAMProvider {
	return &iamProviderImpl{
		sess: newSession(roleARN),
	}
}

func (p *iamProviderImpl) GetRoleArn(roleName string) (string, error) {
	iamService := iam.New(p.sess)
	role, err := iamService.GetRole(&iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return "", err
	}
	return *role.Role.Arn, nil
}

// EC2Provider configures a DNS resolving function for nodes
type EC2Provider interface {
	// Get a node name from instance ID
	GetPrivateDNSName(string) (string, error)
}

type ec2ProviderImpl struct {
	sess            *session.Session
	privateDNSCache map[string]string
	lock            sync.Mutex
}

func NewEC2Provider(roleARN string) EC2Provider {
	return &ec2ProviderImpl{
		sess:            newSession(roleARN),
		privateDNSCache: make(map[string]string),
	}
}

func (p *ec2ProviderImpl) getPrivateDNSNameCache(id string) (string, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	name, ok := p.privateDNSCache[id]
	if ok {
		return name, nil
	}
	return "", errors.New("instance id not found")
}

func (p *ec2ProviderImpl) setPrivateDNSNameCache(id string, privateDNSName string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.privateDNSCache[id] = privateDNSName
}

// GetPrivateDNS looks up the private DNS from the EC2 API
func (p *ec2ProviderImpl) GetPrivateDNSName(id string) (string, error) {
	privateDNSName, err := p.getPrivateDNSNameCache(id)
	if err == nil {
		return privateDNSName, nil
	}

	// Look up instance from EC2 API
	instanceIds := []*string{&id}
	ec2Service := ec2.New(p.sess)
	output, err := ec2Service.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	})
	if err != nil {
		return "", fmt.Errorf("failed querying private DNS from EC2 API for node %s: %s", id, err.Error())
	}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				privateDNSName = aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSNameCache(id, privateDNSName)
			}
		}
	}
	if privateDNSName == "" {
		return "", fmt.Errorf("failed to find node %s", id)
	}
	return privateDNSName, nil
}
