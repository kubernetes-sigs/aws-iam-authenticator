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
	"testing"

	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"

	"github.com/heptio/authenticator/pkg/config"
	"github.com/heptio/authenticator/pkg/token"
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

func setup(verifier token.Verifier) *handler {
	return &handler{
		verifier: verifier,
		metrics:  createMetrics(),
	}
}

func cleanup(m metrics) {
	prometheus.Unregister(m.latency)
	prometheus.Unregister(m.requests)
	prometheus.Unregister(m.malformed)
	prometheus.Unregister(m.invalidToken)
	prometheus.Unregister(m.unknownUser)
	prometheus.Unregister(m.success)
}

// Count of expected metrics
type validateOpts struct {
	// Number of latency entries expected to be recorded.
	latency uint64
	// The expected count for each of the coresponding metrics.
	requests, malformed, invalidToken, unknownUser, success float64
}

func validateMetrics(t *testing.T, opts validateOpts) {
	t.Helper()
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil || len(metrics) == 0 {
		t.Fatalf("Unable to gather metrics to validate they are recorded")
	}
	for _, m := range metrics {
		switch m.GetName() {
		case "heptio_authenticator_aws_authenticate_latency_seconds":
			for _, metric := range m.GetMetric() {
				if metric.GetHistogram().GetSampleCount() != opts.latency {
					t.Errorf("expected %d samples in %s but got %d", opts.latency, m.GetName(), metric.GetHistogram().GetSampleCount())
				}
			}
		case "heptio_authenticator_aws_authenticate_requests":
			for _, metric := range m.GetMetric() {
				if metric.GetCounter().GetValue() != opts.requests {
					t.Errorf("expected %f samples in %s but got %f", opts.requests, m.GetName(), metric.GetCounter().GetValue())
				}
			}
		case "heptio_authenticator_aws_authenticate_malformed_requests":
			for _, metric := range m.GetMetric() {
				if metric.GetCounter().GetValue() != opts.malformed {
					t.Errorf("expected %f samples in %s but got %f", opts.malformed, m.GetName(), metric.GetCounter().GetValue())
				}
			}
		case "heptio_authenticator_aws_authenticate_invalid_token":
			for _, metric := range m.GetMetric() {
				if metric.GetCounter().GetValue() != opts.invalidToken {
					t.Errorf("expected %f samples in %s but got %f", opts.invalidToken, m.GetName(), metric.GetCounter().GetValue())
				}
			}
		case "heptio_authenticator_aws_authenticate_unknown_user":
			for _, metric := range m.GetMetric() {
				if metric.GetCounter().GetValue() != opts.unknownUser {
					t.Errorf("expected %f samples in %s but got %f", opts.unknownUser, m.GetName(), metric.GetCounter().GetValue())
				}
			}
		case "heptio_authenticator_aws_authenticate_success":
			for _, metric := range m.GetMetric() {
				if metric.GetCounter().GetValue() != opts.success {
					t.Errorf("expected %f samples in %s but got %f", opts.unknownUser, m.GetName(), metric.GetCounter().GetValue())
				}
			}
		default:
			if strings.HasPrefix(m.GetName(), "heptio_authenticator_aws_") {
				t.Fatalf("Unknown metric %s", m.GetName())
			}
		}
	}
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
	validateMetrics(t, validateOpts{latency: 1, requests: 1, malformed: 1})
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
	validateMetrics(t, validateOpts{latency: 1, requests: 1, malformed: 1})
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
	validateMetrics(t, validateOpts{latency: 1, requests: 1, malformed: 1})
}

type testVerifier struct {
	identity *token.Identity
	err      error
	param    string
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
	validateMetrics(t, validateOpts{latency: 1, requests: 1, invalidToken: 1})
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
	validateMetrics(t, validateOpts{latency: 1, requests: 1, unknownUser: 1})
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
	h.lowercaseRoleMap = make(map[string]config.RoleMapping)
	h.lowercaseRoleMap["arn:aws:iam::0123456789012:role/test"] = config.RoleMapping{
		RoleARN:  "arn:aws:iam::0123456789012:role/Test",
		Username: "TestUser",
		Groups:   []string{"sys:admin", "listers"},
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("TestUser", "heptio-authenticator-aws:0123456789012:Test", []string{"sys:admin", "listers"}))
	validateMetrics(t, validateOpts{latency: 1, requests: 1, success: 1})
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
	h.lowercaseUserMap = make(map[string]config.UserMapping)
	h.lowercaseUserMap["arn:aws:iam::0123456789012:user/test"] = config.UserMapping{
		UserARN:  "arn:aws:iam::0123456789012:user/Test",
		Username: "TestUser",
		Groups:   []string{"sys:admin", "listers"},
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview("TestUser", "heptio-authenticator-aws:0123456789012:Test", []string{"sys:admin", "listers"}))
	validateMetrics(t, validateOpts{latency: 1, requests: 1, success: 1})
}
