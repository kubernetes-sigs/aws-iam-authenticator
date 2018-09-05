package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"

	"github.com/kubernetes-sigs/aws-iam-authenticator/pkg/config"
	"github.com/kubernetes-sigs/aws-iam-authenticator/pkg/token"
	"github.com/prometheus/client_golang/prometheus"
)

func verifyBodyContains(t *testing.T, resp *httptest.ResponseRecorder, s string) {
	t.Helper()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body from ResponseRecorder, this should not happen")
	}
	if !strings.Contains(string(b), s) {
		t.Errorf("Body did not contain expected value '%s': %s", s, string(b))
	}
}

func verifyAuthResult(t *testing.T, resp *httptest.ResponseRecorder, expected authenticationv1beta1.TokenReview) {
	t.Helper()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body from ResponseRecorder, this should not happen.")
	}
	var actual authenticationv1beta1.TokenReview
	if err = json.Unmarshal(b, &actual); err != nil {
		t.Fatalf("Could not decode TokenReview from body: %s", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("AuthResult did not match expected value; expected: %+v, actual: %+v", expected, actual)
	}
}

func tokenReview(username, uid string, groups []string) authenticationv1beta1.TokenReview {
	return authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
			},
		},
	}
}

type testEC2Provider struct {
	name string
}

func (p *testEC2Provider) getPrivateDNSName(id string) (string, error) {
	return p.name, nil
}

func (p *testEC2Provider) reloadConfig(cng config.Config) {
}

func newTestEC2Provider(name string) *testEC2Provider {
	return &testEC2Provider{
		name: name,
	}
}

func setup(verifier token.Verifier) *handler {
	return &handler{
		verifier:         verifier,
		metrics:          createMetrics(),
		reloadConfigChan: make(chan config.Config, reloadBufferSize),
		lowercaseRoleMap: sync.Map{},
		lowercaseUserMap: sync.Map{},
		accountMap:       sync.Map{},
	}
}

func cleanup(m metrics) {
	prometheus.Unregister(m.latency)
}

// Count of expected metrics
type validateOpts struct {
	// The expected number of latency entries for each label.
	malformed, invalidToken, unknownUser, success, stsError uint64
}

func checkHistogramSampleCount(t *testing.T, name string, actual, expected uint64) {
	t.Helper()
	if actual != expected {
		t.Errorf("expected %d samples histogram heptio_authenticator_aws_authenticate_latency_seconds with labels %s but got %d", expected, name, actual)
	}
}

func validateMetrics(t *testing.T, opts validateOpts) {
	t.Helper()
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil || len(metrics) == 0 {
		t.Fatalf("Unable to gather metrics to validate they are recorded")
	}
	for _, m := range metrics {
		if strings.HasPrefix(m.GetName(), "heptio_authenticator_aws_authenticate_latency_seconds") {
			var actualSuccess, actualMalformed, actualInvalid, actualUnknown, actualSTSError uint64
			for _, metric := range m.GetMetric() {
				if len(metric.Label) != 1 {
					t.Fatalf("Expected 1 label for metric.  Got %+v", metric.Label)
				}
				label := metric.Label[0]
				if *label.Name != "result" {
					t.Fatalf("Expected label to have name 'result' was %s", *label.Name)
				}
				switch *label.Value {
				case metricSuccess:
					actualSuccess = metric.GetHistogram().GetSampleCount()
				case metricMalformed:
					actualMalformed = metric.GetHistogram().GetSampleCount()
				case metricInvalid:
					actualInvalid = metric.GetHistogram().GetSampleCount()
				case metricUnknown:
					actualUnknown = metric.GetHistogram().GetSampleCount()
				case metricSTSError:
					actualSTSError = metric.GetHistogram().GetSampleCount()
				default:
					t.Errorf("Unknown result for latency label: %s", *label.Value)

				}
			}
			checkHistogramSampleCount(t, metricSuccess, actualSuccess, opts.success)
			checkHistogramSampleCount(t, metricMalformed, actualMalformed, opts.malformed)
			checkHistogramSampleCount(t, metricInvalid, actualInvalid, opts.invalidToken)
			checkHistogramSampleCount(t, metricUnknown, actualUnknown, opts.unknownUser)
			checkHistogramSampleCount(t, metricSTSError, actualSTSError, opts.stsError)
		}
	}
}

func TestHandler_Reload(t *testing.T) {
	h := setup(&testVerifier{err: nil})
	h.ec2Provider = newTestEC2Provider("ip-172-31-27-14")

	go h.WatchConfig()
	defer cleanup(h.metrics)

	newCnf := config.Config{
		RoleMappings: []config.RoleMapping{
			{
				RoleARN:  "arn:aws:iam::0123456789012:role/test",
				Username: "role1",
				Groups:   []string{"sys:admin"},
			},
		},
	}

	h.reloadConfigChan <- newCnf

	h.lowercaseRoleMap.Range(func(key interface{}, value interface{}) bool {
		v := value.(config.RoleMapping)
		if v.Username != newCnf.RoleMappings[0].Username {
			t.Error("Unexpected result")
			return false
		}
		if v.RoleARN != newCnf.RoleMappings[0].RoleARN {
			t.Error("Unexpected result")
			return false
		}
		for i, g := range v.Groups {
			if g != newCnf.RoleMappings[0].Groups[i] {
				t.Error("Unexpected result")
				return false
			}
		}
		return true
	})
}

func TestAuthenticateNonPostError(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://k8s.io/authenticate", nil)
	h := setup(nil)
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, was %d", http.StatusMethodNotAllowed, resp.Code)
	}
	verifyBodyContains(t, resp, "expected POST")
	validateMetrics(t, validateOpts{malformed: 1})
}

func TestAuthenticateEmptyBody(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", nil)
	h := setup(nil)
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body")
	validateMetrics(t, validateOpts{malformed: 1})
}

func TestAuthenticateUnableToDecodeBody(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", strings.NewReader("not valid json"))
	h := setup(nil)
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body to be a TokenReview")
	validateMetrics(t, validateOpts{malformed: 1})
}

type testVerifier struct {
	identity *token.Identity
	err      error
	param    string
}

func (v *testVerifier) ReloadConfig(cng config.Config) {
}

func (v *testVerifier) Verify(token string) (*token.Identity, error) {
	v.param = token
	return v.identity, v.err
}

func TestAuthenticateVerifierError(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: errors.New("There was an error")})
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{invalidToken: 1})
}

func TestAuthenticateVerifierSTSError(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: token.NewSTSError("There was an error")})
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{stsError: 1})
}

func TestAuthenticateVerifierNotMapped(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "",
		CanonicalARN: "",
		AccountID:    "",
		UserID:       "",
		SessionName:  "",
	}})
	defer cleanup(h.metrics)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{unknownUser: 1})
}

func TestAuthenticateVerifierRoleMapping(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:role/Test",
		CanonicalARN: "arn:aws:iam::0123456789012:role/Test",
		AccountID:    "0123456789012",
		UserID:       "Test",
		SessionName:  "",
	}})
	defer cleanup(h.metrics)
	h.lowercaseRoleMap = sync.Map{}
	h.lowercaseRoleMap.Store("arn:aws:iam::0123456789012:role/test", config.RoleMapping{
		RoleARN:  "arn:aws:iam::0123456789012:role/Test",
		Username: "TestUser",
		Groups:   []string{"sys:admin", "listers"},
	})
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("TestUser", "aws-iam-authenticator:0123456789012:Test", []string{"sys:admin", "listers"}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierUserMapping(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:user/Test",
		CanonicalARN: "arn:aws:iam::0123456789012:user/Test",
		AccountID:    "0123456789012",
		UserID:       "Test",
		SessionName:  "",
	}})
	defer cleanup(h.metrics)
	h.lowercaseUserMap = sync.Map{}
	h.lowercaseUserMap.Store("arn:aws:iam::0123456789012:user/test", config.UserMapping{
		UserARN:  "arn:aws:iam::0123456789012:user/Test",
		Username: "TestUser",
		Groups:   []string{"sys:admin", "listers"},
	})
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("TestUser", "aws-iam-authenticator:0123456789012:Test", []string{"sys:admin", "listers"}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierAccountMappingForUser(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:user/Test",
		CanonicalARN: "arn:aws:iam::0123456789012:user/Test",
		AccountID:    "0123456789012",
		UserID:       "Test",
		SessionName:  "",
	}})
	defer cleanup(h.metrics)
	h.accountMap = sync.Map{}
	h.accountMap.Store("0123456789012", true)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("arn:aws:iam::0123456789012:user/Test", "aws-iam-authenticator:0123456789012:Test", nil))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierAccountMappingForRole(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:assumed-role/Test/extra",
		CanonicalARN: "arn:aws:iam::0123456789012:role/Test",
		AccountID:    "0123456789012",
		UserID:       "Test",
		SessionName:  "",
	}})
	defer cleanup(h.metrics)
	h.accountMap = sync.Map{}
	h.accountMap.Store("0123456789012", true)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("arn:aws:iam::0123456789012:role/Test", "aws-iam-authenticator:0123456789012:Test", nil))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierNodeMapping(t *testing.T) {
	resp := httptest.NewRecorder()

	data, err := json.Marshal(authenticationv1beta1.TokenReview{
		Spec: authenticationv1beta1.TokenReviewSpec{
			Token: "token",
		},
	})
	if err != nil {
		t.Fatalf("Could not marshal in put data: %v", err)
	}
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", bytes.NewReader(data))
	h := setup(&testVerifier{err: nil, identity: &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:role/TestNodeRole",
		CanonicalARN: "arn:aws:iam::0123456789012:role/TestNodeRole",
		AccountID:    "0123456789012",
		UserID:       "TestNodeRole",
		SessionName:  "i-0c6f21bf1f24f9708",
	}})
	defer cleanup(h.metrics)
	h.ec2Provider = newTestEC2Provider("ip-172-31-27-14")
	h.lowercaseRoleMap = sync.Map{}
	h.lowercaseRoleMap.Store("arn:aws:iam::0123456789012:role/testnoderole", config.RoleMapping{
		RoleARN:  "arn:aws:iam::0123456789012:role/TestNodeRole",
		Username: "system:node:{{EC2PrivateDNSName}}",
		Groups:   []string{"system:nodes", "system:bootstrappers"},
	})
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("system:node:ip-172-31-27-14", "aws-iam-authenticator:0123456789012:TestNodeRole", []string{"system:nodes", "system:bootstrappers"}))
	validateMetrics(t, validateOpts{success: 1})

}
