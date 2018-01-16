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
	return &handler{verifier: verifier}
}

func TestAuthenticateNonPostError(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://k8s.io/authenticate", nil)
	h := setup(nil)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status code %d, was %d", http.StatusMethodNotAllowed, resp.Code)
	}
	verifyBodyContains(t, resp, "expected POST")
}

func TestAuthenticateEmptyBody(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", nil)
	h := setup(nil)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body")
}

func TestAuthenticateUnableToDecodeBody(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", strings.NewReader("not valid json"))
	h := setup(nil)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body to be a TokenReview")
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
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
}
