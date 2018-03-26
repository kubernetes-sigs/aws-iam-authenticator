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

package server

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/heptio/authenticator/pkg/arn"
	"github.com/heptio/authenticator/pkg/config"
	"github.com/heptio/authenticator/pkg/token"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
)

// tokenReviewDenyJSON is a static encoding (at init time) of the 'deny' TokenReview
var tokenReviewDenyJSON = func() []byte {
	res, err := json.Marshal(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: false,
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not create static 'deny' JSON response")
	}
	return res
}()

// server state (internal)
type handler struct {
	http.ServeMux
	lowercaseRoleMap map[string]config.RoleMapping
	lowercaseUserMap map[string]config.UserMapping
	accountMap       map[string]bool
	verifier         token.Verifier
	metrics          metrics
}

// metrics are handles to the collectors for prometheous for the various metrics we are tracking.
type metrics struct {
	latency *prometheus.HistogramVec
}

// namespace for the heptio authenticators metrics
const (
	metricNS        = "heptio_authenticator_aws"
	metricMalformed = "malformed_request"
	metricInvalid   = "invalid_token"
	metricSTSError  = "sts_error"
	metricUnknown   = "uknown_user"
	metricSuccess   = "success"
)

// New creates a new server from a config
func New(config config.Config) *Server {
	return &Server{
		Config: config,
	}
}

// Run the authentication webhook server.
func (c *Server) Run() {
	for _, mapping := range c.RoleMappings {
		logrus.WithFields(logrus.Fields{
			"role":     mapping.RoleARN,
			"username": mapping.Username,
			"groups":   mapping.Groups,
		}).Infof("mapping IAM role")
	}
	for _, mapping := range c.UserMappings {
		logrus.WithFields(logrus.Fields{
			"user":     mapping.UserARN,
			"username": mapping.Username,
			"groups":   mapping.Groups,
		}).Infof("mapping IAM user")
	}
	for _, account := range c.AutoMappedAWSAccounts {
		logrus.WithField("accountID", account).Infof("mapping IAM Account")
	}

	// we always listen on localhost (and run with host networking)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", c.LocalhostPort)
	listenURL := fmt.Sprintf("https://%s/authenticate", listenAddr)

	cert, err := c.GetOrCreateCertificate()
	if err != nil {
		logrus.WithError(err).Fatalf("could not load/generate a certificate")
	}

	if !c.KubeconfigPregenerated {
		if err := c.CreateKubeconfig(); err != nil {
			logrus.WithError(err).Fatalf("could not create kubeconfig")
		}
	}

	// start a TLS listener with our custom certs
	listener, err := tls.Listen("tcp", listenAddr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not open TLS listener")
	}
	defer listener.Close()

	// create a logrus logger for HTTP error logs
	errLog := logrus.WithField("http", "error").Writer()
	defer errLog.Close()

	logrus.Infof("listening on %s", listenURL)
	logrus.Infof("reconfigure your apiserver with `--authentication-token-webhook-config-file=%s` to enable (assuming default hostPath mounts)", c.GenerateKubeconfigPath)
	httpServer := http.Server{
		ErrorLog: log.New(errLog, "", 0),
		Handler:  c.getHandler(),
	}
	logrus.WithError(httpServer.Serve(listener)).Fatal("HTTP server exited")
}

func (c *Server) getHandler() *handler {
	h := &handler{
		lowercaseRoleMap: make(map[string]config.RoleMapping),
		lowercaseUserMap: make(map[string]config.UserMapping),
		accountMap:       make(map[string]bool),
		verifier:         token.NewVerifier(c.ClusterID),
		metrics:          createMetrics(),
	}
	for _, m := range c.RoleMappings {
		canonicalizedARN, err := arn.Canonicalize(strings.ToLower(m.RoleARN))
		if err != nil {
			logrus.Errorf("Error canonicalizing ARN: %v", err)
			continue
		}
		h.lowercaseRoleMap[canonicalizedARN] = m
	}
	for _, m := range c.UserMappings {
		canonicalizedARN, err := arn.Canonicalize(strings.ToLower(m.UserARN))
		if err != nil {
			logrus.Errorf("Error canonicalizing ARN: %v", err)
			continue
		}
		h.lowercaseUserMap[canonicalizedARN] = m
	}

	for _, m := range c.AutoMappedAWSAccounts {
		h.accountMap[m] = true
	}

	h.HandleFunc("/authenticate", h.authenticateEndpoint)
	h.Handle("/metrics", promhttp.Handler())
	return h
}

func createMetrics() metrics {
	m := metrics{
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricNS,
			Name:      "authenticate_latency_seconds",
			Help:      "The latency for authenticate call",
		}, []string{"result"}),
	}
	prometheus.MustRegister(m.latency)
	return m
}

func duration(start time.Time) float64 {
	return time.Since(start).Seconds()
}

func (h *handler) authenticateEndpoint(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	log := logrus.WithFields(logrus.Fields{
		"path":   req.URL.Path,
		"client": req.RemoteAddr,
		"method": req.Method,
	})

	if req.Method != http.MethodPost {
		log.Error("unexpected request method")
		http.Error(w, "expected POST", http.StatusMethodNotAllowed)
		h.metrics.latency.WithLabelValues(metricMalformed).Observe(duration(start))
		return
	}
	if req.Body == nil {
		log.Error("empty request body")
		http.Error(w, "expected a request body", http.StatusBadRequest)
		h.metrics.latency.WithLabelValues(metricMalformed).Observe(duration(start))
		return
	}
	defer req.Body.Close()

	var tokenReview authenticationv1beta1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&tokenReview); err != nil {
		log.WithError(err).Error("could not parse request body")
		http.Error(w, "expected a request body to be a TokenReview", http.StatusBadRequest)
		h.metrics.latency.WithLabelValues(metricMalformed).Observe(duration(start))
		return
	}

	// TODO: rate limit here so we can't be tricked into spamming AWS

	// all responses from here down have JSON bodies
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	// if the token is invalid, reject with a 403
	identity, err := h.verifier.Verify(tokenReview.Spec.Token)
	if err != nil {
		if _, ok := err.(token.STSError); ok {
			h.metrics.latency.WithLabelValues(metricSTSError).Observe(duration(start))
		} else {
			h.metrics.latency.WithLabelValues(metricInvalid).Observe(duration(start))
		}
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	// look up the ARN in each of our mappings to fill in the username and groups
	arnLower := strings.ToLower(identity.CanonicalARN)
	log = log.WithField("arn", identity.CanonicalARN)
	var username string
	var groups []string
	if roleMapping, exists := h.lowercaseRoleMap[arnLower]; exists {
		username = renderTemplate(roleMapping.Username, identity)
		groups = []string{}
		for _, groupPattern := range roleMapping.Groups {
			groups = append(groups, renderTemplate(groupPattern, identity))
		}
	} else if userMapping, exists := h.lowercaseUserMap[arnLower]; exists {
		username = userMapping.Username
		groups = userMapping.Groups
	} else if _, exists := h.accountMap[identity.AccountID]; exists {
		groups = []string{}
		username = identity.CanonicalARN
	} else {
		// if the token has a valid signature but the role is not mapped,
		// deny with a 403 but print a more useful log message
		h.metrics.latency.WithLabelValues(metricUnknown).Observe(duration(start))
		log.Warn("access denied because ARN is not mapped")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	// use a prefixed UID that includes the AWS account ID and AWS user ID ("AROAAAAAAAAAAAAAAAAAA")
	uid := fmt.Sprintf("heptio-authenticator-aws:%s:%s", identity.AccountID, identity.UserID)

	// the token is valid and the role is mapped, return success!
	log.WithFields(logrus.Fields{
		"username": username,
		"uid":      uid,
		"groups":   groups,
	}).Info("access granted")
	h.metrics.latency.WithLabelValues(metricSuccess).Observe(duration(start))
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
			},
		},
	})
}

func renderTemplate(template string, identity *token.Identity) string {
	// usernames and groups must be a DNS-1123 hostname matching the regex
	// "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
	sessionName := strings.Replace(identity.SessionName, "@", "-", -1)

	template = strings.Replace(template, "{{AccountID}}", identity.AccountID, -1)
	template = strings.Replace(template, "{{SessionName}}", sessionName, -1)
	return template
}
