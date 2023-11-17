package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

func TestMain(m *testing.M) {
	metrics.InitMetrics(prometheus.NewRegistry())
	m.Run()
}

func validationErrorTest(t *testing.T, partition string, token string, expectedErr string) {
	t.Helper()

	_, err := NewVerifier("", partition, "").(tokenVerifier).Verify(token)
	errorContains(t, err, expectedErr)
}

func validationSuccessTest(t *testing.T, partition, token string) {
	t.Helper()
	arn := "arn:aws:iam::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	_, err := newVerifier(partition, 200, jsonResponse(arn, account, userID), nil).Verify(token)
	if err != nil {
		t.Errorf("received unexpected error: %s", err)
	}
}

func errorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("err should have contained '%s' was '%s'", expectedErr, err)
	}
}

func assertSTSError(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(STSError); !ok {
		t.Errorf("Expected err %v to be an STSError but was not", err)
	}
}

var (
	now        = time.Now()
	timeStr    = now.UTC().Format("20060102T150405Z")
	validURL   = fmt.Sprintf("https://sts.amazonaws.com/?action=GetCallerIdentity&X-Amz-Credential=ASIABCDEFGHIJKLMNOPQ%%2F20191216%%2Fus-west-2%%2Fs3%%2Faws4_request&x-amz-signedheaders=x-k8s-aws-id&x-amz-expires=60&x-amz-date=%s", timeStr)
	validToken = toToken(validURL)
)

func toToken(url string) string {
	return v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(url))
}

func newVerifier(partition string, statusCode int, body string, err error) Verifier {
	var rc io.ReadCloser
	if body != "" {
		rc = ioutil.NopCloser(bytes.NewReader([]byte(body)))
	}
	return tokenVerifier{
		client: &http.Client{
			Transport: &roundTripper{
				err: err,
				resp: &http.Response{
					StatusCode: statusCode,
					Body:       rc,
				},
			},
		},
		validSTShostnames: stsHostsForPartition(partition, ""),
	}
}

type roundTripper struct {
	err  error
	resp *http.Response
}

type errorReadCloser struct {
}

func (r errorReadCloser) Read(b []byte) (int, error) {
	return 0, errors.New("An Error")
}

func (r errorReadCloser) Close() error {
	return nil
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.resp, rt.err
}

func jsonResponse(arn, account, userid string) string {
	response := getCallerIdentityWrapper{}
	response.GetCallerIdentityResponse.GetCallerIdentityResult.Account = account
	response.GetCallerIdentityResponse.GetCallerIdentityResult.Arn = arn
	response.GetCallerIdentityResponse.GetCallerIdentityResult.UserID = userid
	data, _ := json.Marshal(response)
	return string(data)
}

func TestSTSEndpoints(t *testing.T) {
	cases := []struct {
		partition string
		domain    string
		valid     bool
		region    string
	}{
		{"aws-cn", "sts.cn-northwest-1.amazonaws.com.cn", true, ""},
		{"aws-cn", "sts.cn-north-1.amazonaws.com.cn", true, ""},
		{"aws-cn", "sts.us-iso-east-1.c2s.ic.gov", false, ""},
		{"aws", "sts.amazonaws.com", true, ""},
		{"aws", "sts-fips.us-west-2.amazonaws.com", true, ""},
		{"aws", "sts-fips.us-east-1.amazonaws.com", true, ""},
		{"aws", "sts.us-east-1.amazonaws.com", true, ""},
		{"aws", "sts.us-east-2.amazonaws.com", true, ""},
		{"aws", "sts.us-west-1.amazonaws.com", true, ""},
		{"aws", "sts.us-west-2.amazonaws.com", true, ""},
		{"aws", "sts.ap-south-1.amazonaws.com", true, ""},
		{"aws", "sts.ap-northeast-1.amazonaws.com", true, ""},
		{"aws", "sts.ap-northeast-2.amazonaws.com", true, ""},
		{"aws", "sts.ap-southeast-1.amazonaws.com", true, ""},
		{"aws", "sts.ap-southeast-2.amazonaws.com", true, ""},
		{"aws", "sts.ca-central-1.amazonaws.com", true, ""},
		{"aws", "sts.eu-central-1.amazonaws.com", true, ""},
		{"aws", "sts.eu-west-1.amazonaws.com", true, ""},
		{"aws", "sts.eu-west-2.amazonaws.com", true, ""},
		{"aws", "sts.eu-west-3.amazonaws.com", true, ""},
		{"aws", "sts.eu-north-1.amazonaws.com", true, ""},
		{"aws", "sts.amazonaws.com.cn", false, ""},
		{"aws", "sts.not-a-region.amazonaws.com", false, ""},
		{"aws", "sts.default-region.amazonaws.com", true, "default-region"},
		{"aws-iso", "sts.us-iso-east-1.c2s.ic.gov", true, ""},
		{"aws-iso", "sts.cn-north-1.amazonaws.com.cn", false, ""},
		{"aws-iso-b", "sts.cn-north-1.amazonaws.com.cn", false, ""},
		{"aws-us-gov", "sts.us-gov-east-1.amazonaws.com", true, ""},
		{"aws-us-gov", "sts.amazonaws.com", false, ""},
		{"aws-not-a-partition", "sts.amazonaws.com", false, ""},
	}

	for _, c := range cases {
		verifier := NewVerifier("", c.partition, c.region).(tokenVerifier)
		if err := verifier.verifyHost(c.domain); err != nil && c.valid {
			t.Errorf("%s is not valid endpoint for partition %s", c.domain, c.partition)
		}
	}
}

func TestVerifyTokenPreSTSValidations(t *testing.T) {
	b := make([]byte, maxTokenLenBytes+1, maxTokenLenBytes+1)
	s := string(b)
	validationErrorTest(t, "aws", s, "token is too large")
	validationErrorTest(t, "aws", "k8s-aws-v2.asdfasdfa", "token is missing expected \"k8s-aws-v1.\" prefix")
	validationErrorTest(t, "aws", "k8s-aws-v1.decodingerror", "illegal base64 data")

	validationErrorTest(t, "aws", toToken(":ab:cd.af:/asda"), "missing protocol scheme")
	validationErrorTest(t, "aws", toToken("http://"), "unexpected scheme")
	validationErrorTest(t, "aws", toToken("https://google.com"), fmt.Sprintf("unexpected hostname %q in pre-signed URL", "google.com"))
	validationErrorTest(t, "aws-cn", toToken("https://sts.cn-north-1.amazonaws.com.cn/abc"), "unexpected path in pre-signed URL")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/abc"), "unexpected path in pre-signed URL")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?NoInWhiteList=abc"), "non-whitelisted query parameter")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?action=get&action=post"), "query parameter with multiple values not supported")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?action=NotGetCallerIdenity"), "unexpected action parameter in pre-signed URL")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=abc%3bx-k8s-aws-i%3bdef"), "client did not sign the x-k8s-aws-id header in the pre-signed URL")
	validationErrorTest(t, "aws", toToken(fmt.Sprintf("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=9999999", timeStr)), "invalid X-Amz-Expires parameter in pre-signed URL")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=xxxxxxx&x-amz-expires=60"), "error parsing X-Amz-Date parameter")
	validationErrorTest(t, "aws", toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=19900422T010203Z&x-amz-expires=60"), "X-Amz-Date parameter is expired")
	validationErrorTest(t, "aws", toToken(fmt.Sprintf("https://sts.sa-east-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60%%gh", timeStr)), "input token was not properly formatted: malformed query parameter")
	validationSuccessTest(t, "aws", toToken(fmt.Sprintf("https://sts.us-east-2.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, "aws", toToken(fmt.Sprintf("https://sts.ap-northeast-2.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, "aws", toToken(fmt.Sprintf("https://sts.ca-central-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, "aws", toToken(fmt.Sprintf("https://sts.eu-west-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, "aws", toToken(fmt.Sprintf("https://sts.sa-east-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationErrorTest(t, "aws", toToken(fmt.Sprintf("https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAAAAAAAAAAAAAAAAA%%2F20220601%%2Fus-west-2%%2Fsts%%2Faws4_request&X-Amz-Date=%s&X-Amz-Expires=900&X-Amz-Security-Token=XXXXXXXXXXXXX&X-Amz-SignedHeaders=host%%3Bx-k8s-aws-id&x-amz-credential=eve&X-Amz-Signature=999999999999999999", timeStr)), "input token was not properly formatted: duplicate query parameter found:")
}

func TestVerifyHTTPError(t *testing.T) {
	_, err := newVerifier("aws", 0, "", errors.New("an error")).Verify(validToken)
	errorContains(t, err, "error during GET: an error")
	assertSTSError(t, err)
}

func TestVerifyHTTP403(t *testing.T) {
	_, err := newVerifier("aws", 403, " ", nil).Verify(validToken)
	errorContains(t, err, "error from AWS (expected 200, got")
	assertSTSError(t, err)
}

func TestVerifyNoRedirectsFollowed(t *testing.T) {
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"UserId":"AROAIIRR6I5NDJBWMIRQQ:admin-session","Account":"111122223333","Arn":"arn:aws:sts::111122223333:assumed-role/Admin/admin-session"}`)
	}))
	defer ts2.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts2.URL, http.StatusFound)
	}))
	defer ts.Close()

	tokVerifier := NewVerifier("", "aws", "").(tokenVerifier)

	resp, err := tokVerifier.client.Get(ts.URL)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.Header.Get("Location") != ts2.URL && resp.StatusCode != http.StatusFound {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Printf("%#v\n", resp)
		fmt.Println(string(body))
		t.Error("Unexpectedly followed redirect")
	}
}

func TestVerifyBodyReadError(t *testing.T) {
	verifier := tokenVerifier{
		client: &http.Client{
			Transport: &roundTripper{
				err: nil,
				resp: &http.Response{
					StatusCode: 200,
					Body:       errorReadCloser{},
				},
			},
		},
		validSTShostnames: stsHostsForPartition("aws", ""),
	}
	_, err := verifier.Verify(validToken)
	errorContains(t, err, "error reading HTTP result")
	assertSTSError(t, err)
}

func TestVerifyUnmarshalJSONError(t *testing.T) {
	_, err := newVerifier("aws", 200, "xxxx", nil).Verify(validToken)
	errorContains(t, err, "invalid character")
	assertSTSError(t, err)
}

func TestVerifyInvalidCanonicalARNError(t *testing.T) {
	_, err := newVerifier("aws", 200, jsonResponse("arn", "1000", "userid"), nil).Verify(validToken)
	errorContains(t, err, "arn 'arn' is invalid:")
	assertSTSError(t, err)
}

func TestVerifyInvalidUserIDError(t *testing.T) {
	_, err := newVerifier("aws", 200, jsonResponse("arn:aws:iam::123456789012:role/Alice", "123456789012", "not:vailid:userid"), nil).Verify(validToken)
	errorContains(t, err, "malformed UserID")
	assertSTSError(t, err)
}

func TestVerifyNoSession(t *testing.T) {
	arn := "arn:aws:iam::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	accessKeyID := "ASIABCDEFGHIJKLMNOPQ"
	identity, err := newVerifier("aws", 200, jsonResponse(arn, account, userID), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.AccessKeyID != accessKeyID {
		t.Errorf("expected AccessKeyID to be %q but was %q", accessKeyID, identity.AccessKeyID)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != arn {
		t.Errorf("expected CanonicalARN to be %q but was %q", arn, identity.CanonicalARN)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
}

func TestVerifySessionName(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier("aws", 200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
	if identity.SessionName != session {
		t.Errorf("expected Session to be %q but was %q", session, identity.SessionName)
	}
}

func TestVerifyCanonicalARN(t *testing.T) {
	arn := "arn:aws:sts::123456789012:assumed-role/Alice/extra"
	canonicalARN := "arn:aws:iam::123456789012:role/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier("aws", 200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != canonicalARN {
		t.Errorf("expected CannonicalARN to be %q but was %q", canonicalARN, identity.CanonicalARN)
	}
}

func TestFormatJson(t *testing.T) {
	cases := []struct {
		Name             string
		EnvKey           string
		ExpectApiVersion string
		IsMalformedEnv   bool
	}{
		{
			Name:             "Default",
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "Malformed KUBERNETES_EXEC_INFO",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			IsMalformedEnv:   true,
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "KUBERNETES_EXEC_INFO with v1beta1",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "KUBERNETES_EXEC_INFO with v1",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			ExpectApiVersion: clientauthv1.SchemeGroupVersion.String(),
		},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			expiry, _ := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
			token := "token"
			g, _ := NewGenerator(true, true)

			if c.EnvKey != "" {
				marshal := make([]byte, 0)
				if !c.IsMalformedEnv {
					marshal, _ = json.Marshal(clientauthentication.ExecCredential{
						TypeMeta: v1.TypeMeta{
							Kind:       "ExecCredential",
							APIVersion: c.ExpectApiVersion,
						},
					})
				}

				os.Setenv(c.EnvKey, string(marshal))
			}

			jsonResponse := g.FormatJSON(Token{Token: token, Expiration: expiry})
			output := &clientauthentication.ExecCredential{}
			json.Unmarshal([]byte(jsonResponse), output)

			if output.TypeMeta.Kind != kindExecCredential {
				t.Errorf("expected Kind to be %s but was %s", kindExecCredential, output.TypeMeta.Kind)
			}

			if output.TypeMeta.APIVersion != c.ExpectApiVersion {
				t.Errorf("expected APIVersion to be %s but was %s", c.ExpectApiVersion, output.TypeMeta.APIVersion)
			}

			if output.Status.Token != token {
				t.Errorf("expected token to be %s but was %s", token, output.Status.Token)
			}

			if !output.Status.ExpirationTimestamp.Time.Equal(expiry) {
				t.Errorf("expected expiration to be %s but was %s", expiry, output.Status.ExpirationTimestamp)
			}

			os.Unsetenv(c.EnvKey)
		})
	}
}

func TestGetIdentityFromSTSResponse(t *testing.T) {
	var (
		accessKeyID = "AKIAVVVVVVVVVVVAGAVA"
		defaultID   = Identity{
			AccessKeyID: accessKeyID,
		}
		defaultAccount = "123456789012"
		rootUserARN    = "arn:aws:iam::123456789012:root"
		userARN        = "arn:aws:iam::123456789012:user/Alice"
		userID         = "AIDAIYCCCMMMMMMMMGGDA"
		fedUserID      = "123456789012:Alice"
		fedUserARN     = "arn:aws:sts::123456789012:federated-user/Alice"
		roleARN        = "arn:aws:iam::123456789012:role/Alice"
		roleID         = "AROAZZCCCNNNNNNNNFFFA"
	)

	cases := []struct {
		name          string
		inputID       Identity
		inputResponse getCallerIdentityWrapper
		expectedErr   bool
		want          Identity
	}{
		{
			name:          "Root User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, defaultAccount, rootUserARN),
			expectedErr:   false,
			want: Identity{
				ARN:          rootUserARN,
				CanonicalARN: rootUserARN,
				AccountID:    defaultAccount,
				UserID:       defaultAccount,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, userID, userARN),
			expectedErr:   false,
			want: Identity{
				ARN:          userARN,
				CanonicalARN: userARN,
				AccountID:    defaultAccount,
				UserID:       userID,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "Role",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, roleID, roleARN),
			expectedErr:   false,
			want: Identity{
				ARN:          roleARN,
				CanonicalARN: roleARN,
				AccountID:    defaultAccount,
				UserID:       roleID,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "Federated User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, fedUserID, fedUserARN),
			expectedErr:   false,
			want: Identity{
				ARN:          fedUserARN,
				CanonicalARN: fedUserARN,
				AccountID:    defaultAccount,
				UserID:       fedUserID,
				AccessKeyID:  accessKeyID,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			if got, err := getIdentityFromSTSResponse(&c.inputID, c.inputResponse); err == nil {
				if c.expectedErr {
					t.Errorf("expected err to be nil but was %s", err)
				}

				if diff := cmp.Diff(c.want, *got); diff != "" {
					t.Errorf("getIdentityFromSTSResponse() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func response(account, userID, arn string) getCallerIdentityWrapper {
	wrapper := getCallerIdentityWrapper{}
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.Account = account
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.Arn = arn
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.UserID = userID
	wrapper.GetCallerIdentityResponse.ResponseMetadata.RequestID = "id1234"
	return wrapper
}
