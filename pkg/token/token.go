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

const (
	v1Prefix         = "kubernetes-aws-authenticator-v1."
	maxTokenLenBytes = 1024 * 4
	serverIDHeader   = "x-kubernetes-aws-authenticator-server-id"
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

// Get assumes the given AWS IAM role and returns a kubernetes-aws-authenticator token valid for serverID.
func Get(roleARN string, serverID string) (string, error) {
	// Create a session to share configuration, and load external configuration.
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return "", fmt.Errorf("could not create session: %v", err)
	}

	// create STS-based credentials that will assume the given role
	creds := stscreds.NewCredentials(sess, roleARN)

	// create
	stsAPI := sts.New(sess, &aws.Config{Credentials: creds})

	request, _ := stsAPI.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})

	// set our fixed header as a hardening measure (to prevent some confused deputy vulns)
	request.HTTPRequest.Header.Add(serverIDHeader, serverID)

	presignedURLString, err := request.Presign(60 * time.Second)
	if err != nil {
		return "", err
	}

	// TODO: this may need to be a constant-time base64 encoding
	return v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(presignedURLString)), nil
}

// Verify an kubernetes-aws-authenticator token is valid for the specified serverID
func Verify(token string, serverID string) (string, error) {
	if len(token) > maxTokenLenBytes {
		return "", fmt.Errorf("token is too large")
	}

	if !strings.HasPrefix(token, v1Prefix) {
		return "", fmt.Errorf("token is missing expected %q prefix", v1Prefix)
	}

	// TODO: this may need to be a constant-time base64 decoding
	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, v1Prefix))
	if err != nil {
		return "", err
	}

	parsedURL, err := url.Parse(string(tokenBytes))
	if err != nil {
		return "", err
	}

	if parsedURL.Scheme != "https" {
		return "", fmt.Errorf("unexpected scheme %q in pre-signed URL", parsedURL.Scheme)
	}

	if parsedURL.Host != "sts.amazonaws.com" {
		return "", fmt.Errorf("unexpected hostname in pre-signed URL")
	}

	if parsedURL.Path != "/" {
		return "", fmt.Errorf("unexpected path in pre-signed URL")
	}

	queryParamsLower := make(url.Values)
	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		if !parameterWhitelist[strings.ToLower(key)] {
			return "", fmt.Errorf("non-whitelisted query parameter %q", key)
		}
		if len(values) != 1 {
			return "", fmt.Errorf("query parameter with multiple values not supported")
		}
		queryParamsLower.Set(strings.ToLower(key), values[0])
	}

	if queryParamsLower.Get("action") != "GetCallerIdentity" {
		return "", fmt.Errorf("unexpected action parameter in pre-signed URL")
	}

	if !hasSignedServerIDHeader(&queryParamsLower) {
		return "", fmt.Errorf("client did not sign the %s header in the pre-signed URL", serverIDHeader)
	}

	expires, err := strconv.Atoi(queryParamsLower.Get("x-amz-expires"))
	if err != nil || expires < 0 || expires > 60 {
		return "", fmt.Errorf("invalid X-Amz-Expires parameter in pre-signed URL")
	}

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	req.Header.Set(serverIDHeader, serverID)
	req.Header.Set("accept", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		// special case to avoid printing the full URL if possible
		if urlErr, ok := err.(*url.Error); ok {
			return "", fmt.Errorf("error during GET: %v", urlErr.Err)
		}
		return "", fmt.Errorf("error during GET: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return "", fmt.Errorf("error from AWS (expected 200, got %d)", response.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("error reading HTTP result: %v", err)
	}

	var callerIdentity getCallerIdentityWrapper
	err = json.Unmarshal(responseBody, &callerIdentity)
	if err != nil {
		return "", err
	}

	return canonicalizeARN(callerIdentity.GetCallerIdentityResponse.GetCallerIdentityResult.Arn)
}

func hasSignedServerIDHeader(paramsLower *url.Values) bool {
	signedHeaders := strings.Split(paramsLower.Get("x-amz-signedheaders"), ";")
	for _, hdr := range signedHeaders {
		if strings.ToLower(hdr) == strings.ToLower(serverIDHeader) {
			return true
		}
	}
	return false
}

var assumedRoleARNPattern = regexp.MustCompile(
	`\Aarn:aws:sts::([\d]{12}):assumed-role/([\w+=,.@-]+)/([\w+=,.@-]*)\z`,
)

func canonicalizeARN(arn string) (string, error) {
	parts := assumedRoleARNPattern.FindStringSubmatch(arn)
	if len(parts) != 4 {
		return "", fmt.Errorf("malformed ARN %q", arn)
	}
	accountID, roleName := parts[1], parts[2]
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName), nil
}
