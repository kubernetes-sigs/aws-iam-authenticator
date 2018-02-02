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

package token

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

// Identity is returned on successful Verify() results. It contains a parsed
// version of the AWS identity used to create the token.
type Identity struct {
	// ARN is the raw Amazon Resource Name returned by sts:GetCallerIdentity
	ARN string

	// CanonicalARN is the Amazon Resource Name converted to a more canonical
	// representation. In particular, STS assumed role ARNs like
	// "arn:aws:sts::ACCOUNTID:assumed-role/ROLENAME/SESSIONNAME" are converted
	// to their IAM ARN equivalent "arn:aws:iam::ACCOUNTID:role/NAME"
	CanonicalARN string

	// AccountID is the 12 digit AWS account number.
	AccountID string

	// UserID is the unique user/role ID (e.g., "AROAAAAAAAAAAAAAAAAAA").
	UserID string

	// IAM user or role name
	Name string

	// SessionName is the STS session name (or "" if this is not a
	// session-based identity). For EC2 instance roles, this will be the EC2
	// instance ID (e.g., "i-0123456789abcdef0"). You should only rely on it
	// if you trust that _only_ EC2 is allowed to assume the IAM Role. If IAM
	// users or other roles are allowed to assume the role, they can provide
	// (nearly) arbitrary strings here.
	SessionName string
}

const (
	v1Prefix         = "k8s-aws-v1."
	maxTokenLenBytes = 1024 * 4
	clusterIDHeader  = "x-k8s-aws-id"
)

var parameterWhitelist = map[string]bool{
	"action":               true,
	"version":              true,
	"x-amz-algorithm":      true,
	"x-amz-credential":     true,
	"x-amz-date":           true,
	"x-amz-expires":        true,
	"x-amz-security-token": true,
	"x-amz-signature":      true,
	"x-amz-signedheaders":  true,
}

// this is the result type from the GetCallerIdentity endpoint
type getCallerIdentityWrapper struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`
}

// Generator provides new tokens for the heptio authenticator.
type Generator interface {
	// Get a token using credentials in the default credentials chain.
	Get(string) (string, error)
	// GetWithRole creates a token by assuming the provided role, using the credentials in the default chain.
	GetWithRole(clusterID, roleARN string) (string, error)
}

type generator struct {
}

// NewGenerator creates a Generator and returns it.
func NewGenerator() (Generator, error) {
	return generator{}, nil
}

// Get uses the directly available AWS credentials to return a token valid for
// clusterID. It follows the default AWS credential handling behavior.
func (g generator) Get(clusterID string) (string, error) {
	return g.GetWithRole(clusterID, "")
}

// GetWithRole assumes the given AWS IAM role and returns a token valid for
// clusterID. If roleARN is empty, behaves like Get (does not assume a role).
func (g generator) GetWithRole(clusterID string, roleARN string) (string, error) {
	// create a session with the "base" credentials available
	// (from environment variable, profile files, EC2 metadata, etc)
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return "", fmt.Errorf("could not create session: %v", err)
	}

	// use an STS client based on the direct credentials
	stsAPI := sts.New(sess)

	// if a roleARN was specified, replace the STS client with one that uses
	// temporary credentials from that role.
	if roleARN != "" {
		// create STS-based credentials that will assume the given role
		creds := stscreds.NewCredentials(sess, roleARN)

		// create an STS API interface that uses the assumed role's temporary credentials
		stsAPI = sts.New(sess, &aws.Config{Credentials: creds})
	}

	// generate an sts:GetCallerIdentity request and add our custom cluster ID header
	request, _ := stsAPI.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	request.HTTPRequest.Header.Add(clusterIDHeader, clusterID)

	// sign the request
	presignedURLString, err := request.Presign(60 * time.Second)
	if err != nil {
		return "", err
	}

	// TODO: this may need to be a constant-time base64 encoding
	return v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString)), nil
}

// Verifier validates tokens by calling STS and returning the associated identity.
type Verifier interface {
	Verify(token string) (*Identity, error)
}

type tokenVerifier struct {
	client    *http.Client
	clusterID string
}

// NewVerifier creates a Verifier that is bound to the clusterID and uses the default http client.
func NewVerifier(clusterID string) Verifier {
	return tokenVerifier{
		client:    http.DefaultClient,
		clusterID: clusterID,
	}
}

// Verify a token is valid for the specified clusterID. On success, returns an
// Identity that contains information about the AWS principal that created the
// token. On failure, returns nil and a non-nil error.
func (v tokenVerifier) Verify(token string) (*Identity, error) {
	if len(token) > maxTokenLenBytes {
		return nil, fmt.Errorf("token is too large")
	}

	if !strings.HasPrefix(token, v1Prefix) {
		return nil, fmt.Errorf("token is missing expected %q prefix", v1Prefix)
	}

	// TODO: this may need to be a constant-time base64 decoding
	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, v1Prefix))
	if err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(string(tokenBytes))
	if err != nil {
		return nil, err
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("unexpected scheme %q in pre-signed URL", parsedURL.Scheme)
	}

	if parsedURL.Host != "sts.amazonaws.com" {
		return nil, fmt.Errorf("unexpected hostname in pre-signed URL")
	}

	if parsedURL.Path != "/" {
		return nil, fmt.Errorf("unexpected path in pre-signed URL")
	}

	queryParamsLower := make(url.Values)
	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		if !parameterWhitelist[strings.ToLower(key)] {
			return nil, fmt.Errorf("non-whitelisted query parameter %q", key)
		}
		if len(values) != 1 {
			return nil, fmt.Errorf("query parameter with multiple values not supported")
		}
		queryParamsLower.Set(strings.ToLower(key), values[0])
	}

	if queryParamsLower.Get("action") != "GetCallerIdentity" {
		return nil, fmt.Errorf("unexpected action parameter in pre-signed URL")
	}

	if !hasSignedClusterIDHeader(&queryParamsLower) {
		return nil, fmt.Errorf("client did not sign the %s header in the pre-signed URL", clusterIDHeader)
	}

	expires, err := strconv.Atoi(queryParamsLower.Get("x-amz-expires"))
	if err != nil || expires < 0 || expires > 60 {
		return nil, fmt.Errorf("invalid X-Amz-Expires parameter in pre-signed URL")
	}

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	req.Header.Set(clusterIDHeader, v.clusterID)
	req.Header.Set("accept", "application/json")

	response, err := v.client.Do(req)
	if err != nil {
		// special case to avoid printing the full URL if possible
		if urlErr, ok := err.(*url.Error); ok {
			return nil, fmt.Errorf("error during GET: %v", urlErr.Err)
		}
		return nil, fmt.Errorf("error during GET: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("error from AWS (expected 200, got %d)", response.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading HTTP result: %v", err)
	}

	var callerIdentity getCallerIdentityWrapper
	err = json.Unmarshal(responseBody, &callerIdentity)
	if err != nil {
		return nil, err
	}

	// parse the response into an Identity
	id := &Identity{
		ARN:       callerIdentity.GetCallerIdentityResponse.GetCallerIdentityResult.Arn,
		AccountID: callerIdentity.GetCallerIdentityResponse.GetCallerIdentityResult.Account,
	}
	id.CanonicalARN, err = canonicalizeARN(id.ARN)
	if err != nil {
		return nil, err
	}

	id.Name, err = nameFromCanonicalARN(id.CanonicalARN)
	if err != nil {
		return nil, err
	}

	// The user ID is either UserID:SessionName (for assumed roles) or just
	// UserID (for IAM User principals).
	userIDParts := strings.Split(callerIdentity.GetCallerIdentityResponse.GetCallerIdentityResult.UserID, ":")
	if len(userIDParts) == 2 {
		id.UserID = userIDParts[0]
		id.SessionName = userIDParts[1]
	} else if len(userIDParts) == 1 {
		id.UserID = userIDParts[0]
	} else {
		return nil, fmt.Errorf(
			"malformed UserID %q",
			callerIdentity.GetCallerIdentityResponse.GetCallerIdentityResult.UserID)
	}

	return id, nil
}

func hasSignedClusterIDHeader(paramsLower *url.Values) bool {
	signedHeaders := strings.Split(paramsLower.Get("x-amz-signedheaders"), ";")
	for _, hdr := range signedHeaders {
		if strings.ToLower(hdr) == strings.ToLower(clusterIDHeader) {
			return true
		}
	}
	return false
}

var assumedRoleARNPattern = regexp.MustCompile(
	`\Aarn:aws:sts::([\d]{12}):assumed-role/([\w+=,.@-]+)/([\w+=,.@-]*)\z`,
)

var userARNPattern = regexp.MustCompile(
	`\Aarn:aws:iam::([\d]{12}):user/([\w+=,.@-]+)\z`,
)

func canonicalizeARN(arn string) (string, error) {
	// we'll say that user ARNs are already canonical
	if userARNPattern.MatchString(arn) {
		return arn, nil
	}

	// convert assumed-role ARNs to the more common arn:aws:iam::ACCOUNT:role/NAME format
	parts := assumedRoleARNPattern.FindStringSubmatch(arn)
	if parts != nil && len(parts) == 4 {
		accountID, roleName := parts[1], parts[2]
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName), nil
	}

	// otherwise we don't understand this ARN format so return an error
	return "", fmt.Errorf("malformed ARN %q", arn)
}

func nameFromCanonicalARN(arn string) (string, error) {
	arnSlice := strings.Split(arn, "/")
	name := arnSlice[len(arnSlice)-1]
	if name != "" {
		return name, nil
	}
	return "", fmt.Errorf("malformed ARN %q", arn)
}
