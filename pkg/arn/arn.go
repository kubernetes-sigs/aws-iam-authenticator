// Package arn provides utilities for parsing and validating AWS ARNs used in IAM authentication.
package arn

import (
	"fmt"
	"slices"
	"strings"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/endpoints"
)

// PrincipalType represents the type of AWS principal (role, user, etc).
type PrincipalType int

const (
	// NONE indicates no principal type is set.
	NONE PrincipalType = iota
	// ROLE indicates an IAM role principal.
	ROLE
	// USER indicates an IAM user principal.
	USER
	// ROOT indicates an AWS root account principal.
	ROOT
	FEDERATED_USER //nolint:revive // var-naming: ALL_CAPS preserved for backwards compatibility
	ASSUMED_ROLE   //nolint:revive // var-naming: ALL_CAPS preserved for backwards compatibility
)

// Canonicalize validates IAM resources are appropriate for the authenticator
// and converts STS assumed roles into the IAM role resource.
//
// Supported IAM resources are:
//   - AWS root user: arn:aws:iam::123456789012:root
//   - IAM user: arn:aws:iam::123456789012:user/Bob
//   - IAM role: arn:aws:iam::123456789012:role/S3Access
//   - IAM Assumed role: arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary (converted to IAM role)
//   - Federated user: arn:aws:sts::123456789012:federated-user/Bob
func Canonicalize(arn string) (PrincipalType, string, error) {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return NONE, "", fmt.Errorf("arn '%s' is invalid: '%v'", arn, err)
	}

	if err := checkPartition(parsed.Partition); err != nil {
		return NONE, "", fmt.Errorf("arn '%s' does not have a recognized partition", arn)
	}

	parts := strings.Split(parsed.Resource, "/")
	resource := parts[0]

	switch parsed.Service {
	case "sts":
		switch resource {
		case "federated-user":
			return FEDERATED_USER, arn, nil
		case "assumed-role":
			if len(parts) < 3 {
				return NONE, "", fmt.Errorf("assumed-role arn '%s' does not have a role", arn)
			}
			// IAM ARNs can contain paths, part[0] is resource, parts[len(parts)] is the SessionName.
			role := strings.Join(parts[1:len(parts)-1], "/")
			return ASSUMED_ROLE, fmt.Sprintf("arn:%s:iam::%s:role/%s", parsed.Partition, parsed.AccountID, role), nil
		default:
			return NONE, "", fmt.Errorf("unrecognized resource %s for service sts", parsed.Resource)
		}
	case "iam":
		switch resource {
		case "role":
			return ROLE, arn, nil
		case "user":
			return USER, arn, nil
		case "root":
			return ROOT, arn, nil
		default:
			return NONE, "", fmt.Errorf("unrecognized resource %s for service iam", parsed.Resource)
		}
	}

	return NONE, "", fmt.Errorf("service %s in arn %s is not a valid service for identities", parsed.Service, arn)
}

// StripPath removes the path component from an ARN.
// TODO: add strip path functionality Canonicalize after testing it in all mappers - this can be used to support role paths in the configmap
func StripPath(arn string) (string, error) {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return "", fmt.Errorf("arn '%s' is invalid: '%v'", arn, err)
	}

	if err := checkPartition(parsed.Partition); err != nil {
		return "", fmt.Errorf("arn '%s' does not have a recognized partition", arn)
	}

	parts := strings.Split(parsed.Resource, "/")
	resource := parts[0]

	if resource != "role" {
		return arn, nil
	}

	if len(parts) > 2 {
		// Stripping off the path means we just need to keep the first and last part of the arn resource
		// role/path/for/this-role/matt -> role/matt
		role := parts[len(parts)-1]
		return fmt.Sprintf("arn:%s:iam::%s:role/%s", parsed.Partition, parsed.AccountID, role), nil
	}
	return arn, nil
}

func checkPartition(partition string) error {
	if !slices.Contains(endpoints.PARTITIONS, partition) {
		return fmt.Errorf("partition %s is not recognized", partition)
	}
	return nil
}
