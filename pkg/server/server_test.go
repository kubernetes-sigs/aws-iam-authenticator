package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd"
	iamauthenticatorv1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/apis/iamauthenticator/v1alpha1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd/controller"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/file"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func verifyBodyContains(t *testing.T, resp *httptest.ResponseRecorder, s string) {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body from ResponseRecorder, this should not happen")
	}
	if !strings.Contains(string(b), s) {
		t.Errorf("Body did not contain expected value '%s': %s", s, string(b))
	}
}

func verifyAuthResult(t *testing.T, resp *httptest.ResponseRecorder, expected authenticationv1beta1.TokenReview) {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
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

func tokenReview(username, uid string, groups []string, extrasMap map[string]authenticationv1beta1.ExtraValue) authenticationv1beta1.TokenReview {
	return authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
				Extra:    extrasMap,
			},
		},
	}
}

type testEC2Provider struct {
	name  string
	qps   int
	burst int
}

func (p *testEC2Provider) GetPrivateDNSName(id string) (string, error) {
	return p.name, nil
}

func (p *testEC2Provider) StartEc2DescribeBatchProcessing() {}

func newTestEC2Provider(name string, qps int, burst int) *testEC2Provider {
	return &testEC2Provider{
		name:  name,
		qps:   qps,
		burst: burst,
	}
}

func newIAMIdentityMapping(arn, canonicalARN, username string, groups []string) *iamauthenticatorv1alpha1.IAMIdentityMapping {
	return &iamauthenticatorv1alpha1.IAMIdentityMapping{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-iam-identity-mapping",
		},
		Spec: iamauthenticatorv1alpha1.IAMIdentityMappingSpec{
			ARN:      arn,
			Username: username,
			Groups:   groups,
		},
		Status: iamauthenticatorv1alpha1.IAMIdentityMappingStatus{
			CanonicalARN: canonicalARN,
		},
	}
}

func setup(verifier token.Verifier) *handler {
	metrics.InitMetrics(prometheus.NewRegistry())
	return &handler{
		verifier: verifier,
	}
}

func createIndexer() cache.Indexer {
	return cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		"canonicalARN": controller.IndexIAMIdentityMappingByCanonicalArn,
	})
}

// Count of expected metrics
type validateOpts struct {
	// The expected number of latency entries for each label.
	malformed, invalidToken, unknownUser, success, stsError, stsThrottling uint64
}

func checkHistogramSampleCount(t *testing.T, name string, actual, expected uint64) {
	t.Helper()
	if actual != expected {
		t.Errorf("expected %d samples histogram aws_iam_authenticator_authenticate_latency_seconds with labels %s but got %d", expected, name, actual)
	}
}

func validateMetrics(t *testing.T, opts validateOpts) {
	t.Helper()
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil || len(metricFamilies) == 0 {
		t.Fatalf("Unable to gather metrics to validate they are recorded")
	}
	for _, m := range metricFamilies {
		if strings.HasPrefix(m.GetName(), "aws_iam_authenticator_authenticate_latency_seconds") {
			var actualSuccess, actualMalformed, actualInvalid, actualUnknown, actualSTSError, actualSTSThrottling uint64
			for _, metric := range m.GetMetric() {
				if len(metric.Label) != 1 {
					t.Fatalf("Expected 1 label for metric.  Got %+v", metric.Label)
				}
				label := metric.Label[0]
				if *label.Name != "result" {
					t.Fatalf("Expected label to have name 'result' was %s", *label.Name)
				}
				switch *label.Value {
				case metrics.Success:
					actualSuccess = metric.GetHistogram().GetSampleCount()
				case metrics.Malformed:
					actualMalformed = metric.GetHistogram().GetSampleCount()
				case metrics.Invalid:
					actualInvalid = metric.GetHistogram().GetSampleCount()
				case metrics.Unknown:
					actualUnknown = metric.GetHistogram().GetSampleCount()
				case metrics.STSError:
					actualSTSError = metric.GetHistogram().GetSampleCount()
				case metrics.STSThrottling:
					actualSTSThrottling = metric.GetHistogram().GetSampleCount()
				default:
					t.Errorf("Unknown result for latency label: %s", *label.Value)

				}
			}
			checkHistogramSampleCount(t, metrics.Success, actualSuccess, opts.success)
			checkHistogramSampleCount(t, metrics.Malformed, actualMalformed, opts.malformed)
			checkHistogramSampleCount(t, metrics.Invalid, actualInvalid, opts.invalidToken)
			checkHistogramSampleCount(t, metrics.Unknown, actualUnknown, opts.unknownUser)
			checkHistogramSampleCount(t, metrics.STSError, actualSTSError, opts.stsError)
			checkHistogramSampleCount(t, metrics.STSThrottling, actualSTSThrottling, opts.stsThrottling)
		}
	}
}

func TestReservedPrefixExists(t *testing.T) {
	cases := []struct {
		username     string
		reservedList []string
		want         bool
	}{
		{
			"system:masters",
			[]string{"aws:", "eks:", "amazon:", "iam:", "system:"},
			true,
		},
		{
			"test",
			[]string{"aws:", "eks:", "amazon:", "iam:", "system:"},
			false,
		},
		{
			"eksb:test",
			[]string{"aws:", "eks:", "amazon:", "iam:", "system:"},
			false,
		},
		{
			"eks:test",
			[]string{"aws:", "eks:", "amazon:", "iam:", "system:"},
			true,
		},
	}
	for _, c := range cases {
		if got := ReservedPrefixExists(c.username, c.reservedList); got != c.want {
			t.Errorf(
				"Unexpected result: ReservedPrefixExists(%v,%v): got: %t, wanted %t",
				c.username,
				c.reservedList,
				got,
				c.want,
			)
		}
	}
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
	validateMetrics(t, validateOpts{malformed: 1})
}

func TestAuthenticateNonPostErrorCRD(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://k8s.io/authenticate", nil)
	h := setup(nil)
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body")
	validateMetrics(t, validateOpts{malformed: 1})
}

func TestAuthenticateEmptyBodyCRD(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", nil)
	h := setup(nil)
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body to be a TokenReview")
	validateMetrics(t, validateOpts{malformed: 1})
}

func TestAuthenticateUnableToDecodeBodyCRD(t *testing.T) {
	resp := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://k8s.io/authenticate", strings.NewReader("not valid json"))
	h := setup(nil)
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, was %d", http.StatusBadRequest, resp.Code)
	}
	verifyBodyContains(t, resp, "expected a request body to be a TokenReview")
	validateMetrics(t, validateOpts{malformed: 1})
}

func testIsLoggableIdentity(t *testing.T) {
	h := &handler{scrubbedAccounts: []string{"111122223333", "012345678901"}}

	cases := []struct {
		identity *token.Identity
		want     bool
	}{
		{
			&token.Identity{AccountID: "222233334444"},
			true,
		},
		{
			&token.Identity{AccountID: "111122223333"},
			false,
		},
	}

	for _, c := range cases {
		if got := h.isLoggableIdentity(c.identity); got != c.want {
			t.Errorf(
				"Unexpected result: isLoggableIdentity(%v): got: %t, wanted %t",
				c.identity,
				got,
				c.want,
			)
		}
	}

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
	validateMetrics(t, validateOpts{invalidToken: 1})
}

func TestAuthenticateVerifierErrorCRD(t *testing.T) {
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
	validateMetrics(t, validateOpts{invalidToken: 1})
}

func TestAuthenticateVerifierSTSThrottling(t *testing.T) {
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
	h := setup(&testVerifier{err: token.STSThrottling{}})
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status code %d, was %d", http.StatusTooManyRequests, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{stsThrottling: 1})
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{stsError: 1})
}

func TestAuthenticateVerifierSTSErrorCRD(t *testing.T) {
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
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, was %d", http.StatusForbidden, resp.Code)
	}
	verifyBodyContains(t, resp, string(tokenReviewDenyJSON))
	validateMetrics(t, validateOpts{unknownUser: 1})
}

func TestAuthenticateVerifierNotMappedCRD(t *testing.T) {
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
	identity := &token.Identity{
		ARN:          "arn:aws:iam::0123456789012:role/Test",
		CanonicalARN: "arn:aws:iam::0123456789012:role/Test",
		AccountID:    "0123456789012",
		UserID:       "Test",
		SessionName:  "TestSession",
		AccessKeyID:  "ABCDEF",
	}
	h := setup(&testVerifier{err: nil, identity: identity})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{file.NewFileMapperWithMaps(map[string]config.RoleMapping{
			"arn:aws:iam::0123456789012:role/test": config.RoleMapping{
				RoleARN:  "arn:aws:iam::0123456789012:role/Test",
				Username: "TestUser",
				Groups:   []string{"sys:admin", "listers"},
			},
		}, nil, nil)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"TestUser",
		"aws-iam-authenticator:0123456789012:Test",
		[]string{"sys:admin", "listers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{"ABCDEF"},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierRoleMappingCRD(t *testing.T) {
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
		SessionName:  "TestSession",
	}})
	indexer := createIndexer()
	indexer.Add(newIAMIdentityMapping("arn:aws:iam::0123456789012:role/Test", "arn:aws:iam::0123456789012:role/test", "TestUser", []string{"sys:admin", "listers"}))
	h.backendMapper = BackendMapper{
		mappers:      []mapper.Mapper{crd.NewCRDMapperWithIndexer(indexer)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"TestUser",
		"aws-iam-authenticator:0123456789012:Test",
		[]string{"sys:admin", "listers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
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
		SessionName:  "TestSession",
	}})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{file.NewFileMapperWithMaps(nil, map[string]config.UserMapping{
			"arn:aws:iam::0123456789012:user/test": config.UserMapping{
				UserARN:  "arn:aws:iam::0123456789012:user/Test",
				Username: "TestUser",
				Groups:   []string{"sys:admin", "listers"},
			},
		}, nil)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"TestUser",
		"aws-iam-authenticator:0123456789012:Test",
		[]string{"sys:admin", "listers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierUserMappingCRD(t *testing.T) {
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
		SessionName:  "TestSession",
	}})
	indexer := createIndexer()
	indexer.Add(newIAMIdentityMapping("arn:aws:iam::0123456789012:user/Test", "arn:aws:iam::0123456789012:user/test", "TestUser", []string{"sys:admin", "listers"}))
	h.backendMapper = BackendMapper{
		mappers:      []mapper.Mapper{crd.NewCRDMapperWithIndexer(indexer)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"TestUser",
		"aws-iam-authenticator:0123456789012:Test",
		[]string{"sys:admin", "listers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
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
		SessionName:  "TestSession",
	}})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{file.NewFileMapperWithMaps(nil, nil, map[string]bool{
			"0123456789012": true,
		})},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"arn:aws:iam::0123456789012:user/Test",
		"aws-iam-authenticator:0123456789012:Test",
		nil,
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierAccountMappingForUserCRD(t *testing.T) {
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
		SessionName:  "TestSession",
	}})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{crd.NewCRDMapperWithIndexer(createIndexer()), file.NewFileMapperWithMaps(nil, nil, map[string]bool{
			"0123456789012": true,
		})},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"arn:aws:iam::0123456789012:user/Test",
		"aws-iam-authenticator:0123456789012:Test",
		nil,
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:user/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
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
		SessionName:  "TestSession",
	}})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{file.NewFileMapperWithMaps(nil, nil, map[string]bool{
			"0123456789012": true,
		})},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"arn:aws:iam::0123456789012:role/Test",
		"aws-iam-authenticator:0123456789012:Test",
		nil,
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:assumed-role/Test/extra"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
	validateMetrics(t, validateOpts{success: 1})
}

func TestAuthenticateVerifierAccountMappingForRoleCRD(t *testing.T) {
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
		SessionName:  "TestSession",
	}})
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{crd.NewCRDMapperWithIndexer(createIndexer()), file.NewFileMapperWithMaps(nil, nil, map[string]bool{
			"0123456789012": true,
		})},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"arn:aws:iam::0123456789012:role/Test",
		"aws-iam-authenticator:0123456789012:Test",
		nil,
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:assumed-role/Test/extra"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/Test"},
			"sessionName":  authenticationv1beta1.ExtraValue{"TestSession"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"Test"},
		}))
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
	h.ec2Provider = newTestEC2Provider("ip-172-31-27-14", 15, 5)
	h.backendMapper = BackendMapper{
		mappers: []mapper.Mapper{file.NewFileMapperWithMaps(map[string]config.RoleMapping{
			"arn:aws:iam::0123456789012:role/testnoderole": config.RoleMapping{
				RoleARN:  "arn:aws:iam::0123456789012:role/TestNodeRole",
				Username: "system:node:{{EC2PrivateDNSName}}",
				Groups:   []string{"system:nodes", "system:bootstrappers"},
			},
		}, nil, nil)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"system:node:ip-172-31-27-14",
		"aws-iam-authenticator:0123456789012:TestNodeRole",
		[]string{"system:nodes", "system:bootstrappers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/TestNodeRole"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/TestNodeRole"},
			"sessionName":  authenticationv1beta1.ExtraValue{"i-0c6f21bf1f24f9708"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"TestNodeRole"},
		}))
	validateMetrics(t, validateOpts{success: 1})

}

func TestAuthenticateVerifierNodeMappingCRD(t *testing.T) {
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
	h.ec2Provider = newTestEC2Provider("ip-172-31-27-14", 15, 5)
	indexer := createIndexer()
	indexer.Add(newIAMIdentityMapping("arn:aws:iam::0123456789012:role/TestNodeRole", "arn:aws:iam::0123456789012:role/testnoderole", "system:node:{{EC2PrivateDNSName}}", []string{"system:nodes", "system:bootstrappers"}))
	h.backendMapper = BackendMapper{
		mappers:      []mapper.Mapper{crd.NewCRDMapperWithIndexer(indexer)},
		mapperStopCh: make(chan struct{}),
	}
	h.authenticateEndpoint(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status code %d, was %d", http.StatusOK, resp.Code)
	}
	verifyAuthResult(t, resp, tokenReview(
		"system:node:ip-172-31-27-14",
		"aws-iam-authenticator:0123456789012:TestNodeRole",
		[]string{"system:nodes", "system:bootstrappers"},
		map[string]authenticationv1beta1.ExtraValue{
			"arn":          authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/TestNodeRole"},
			"canonicalArn": authenticationv1beta1.ExtraValue{"arn:aws:iam::0123456789012:role/TestNodeRole"},
			"sessionName":  authenticationv1beta1.ExtraValue{"i-0c6f21bf1f24f9708"},
			"accessKeyId":  authenticationv1beta1.ExtraValue{""},
			"principalId":  authenticationv1beta1.ExtraValue{"TestNodeRole"},
		}))
	validateMetrics(t, validateOpts{success: 1})

}

func TestRenderTemplate(t *testing.T) {
	h := &handler{}
	h.ec2Provider = newTestEC2Provider("ip-172-31-27-14", 15, 5)
	cases := []struct {
		template string
		want     string
		identity token.Identity
		err      bool
	}{
		{
			template: "a-{{EC2PrivateDNSName}}-b",
			want:     "a-ip-172-31-27-14-b",
			identity: token.Identity{
				SessionName: "i-aaaaaaaa",
			},
		},
		{
			template: "a-{{EC2PrivateDNSName}}-b",
			want:     "a-ip-172-31-27-14-b",
			identity: token.Identity{
				SessionName: "i-aaaaa",
			},
			err: true,
		},
		{
			template: "a-{{AccountID}}-b",
			want:     "a-123-b",
			identity: token.Identity{
				AccountID: "123",
			},
		},
		{
			template: "a-{{AccessKeyID}}-b",
			want:     "a-321-b",
			identity: token.Identity{
				AccessKeyID: "321",
			},
		},
		{
			template: "a-{{SessionName}}-b",
			want:     "a-jdoe-b",
			identity: token.Identity{
				SessionName: "jdoe",
			},
		},
		{
			template: "a-{{SessionName}}-b",
			want:     "a-jdoe-example.com-b",
			identity: token.Identity{
				SessionName: "jdoe@example.com",
			},
		},
		{
			template: "a-{{SessionNameRaw}}-b",
			want:     "a-jdoe@example.com-b",
			identity: token.Identity{
				SessionName: "jdoe@example.com",
			},
		},
		{
			template: "a-{{AccountID}}-{{SessionName}}-{{SessionNameRaw}}-b",
			want:     "a-123-jdoe-example.com-jdoe@example.com-b",
			identity: token.Identity{
				AccountID:   "123",
				SessionName: "jdoe@example.com",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.template, func(t *testing.T) {
			got, err := h.renderTemplate(c.template, &c.identity)
			if err != nil {
				if c.err {
					return
				}
				t.Errorf("unexpected error: %s", err.Error())
			} else if c.err {
				t.Errorf("expected error")
			}
			if got != c.want {
				t.Errorf("want: %v, got: %v", c.want, got)
			}

		})
	}
}

func TestCallBackForFileLoad(t *testing.T) {
	fileContent := strings.Split(string("DynamicFile,MountedFile"), ",")

	cfg := config.Config{
		DynamicFilePath: "/tmp/server_test.txt",
	}
	h := &handler{
		cfg: cfg,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newMapper, err := BuildMapperChain(ctx, h.cfg, fileContent)
	if err != nil {
		t.Errorf("Fail in TestCallBackForFileLoad: BuildMapperChain")
	}
	if len(newMapper.mappers) != len(fileContent) {
		t.Errorf("Fail in TestCallBackForFileLoad: unpected mapper length")
	}
	if newMapper.mappers[0].Name() != "DynamicFile" {
		t.Errorf("Fail in TestCallBackForFileLoad: unpected mapper mode")
	}
	if newMapper.mappers[1].Name() != "MountedFile" {
		t.Errorf("Fail in TestCallBackForFileLoad: unpected mapper mode")
	}
}
