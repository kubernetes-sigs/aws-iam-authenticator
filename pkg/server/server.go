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
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heptio/authenticator/pkg/arn"
	"github.com/heptio/authenticator/pkg/config"
	"github.com/heptio/authenticator/pkg/token"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
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
	lowercaseNodeMap map[string]config.NodeMapping
	accountMap       map[string]bool
	verifier         token.Verifier
	metrics          metrics
	nodeNameProvider NodeNameProvider
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
	for _, mapping := range c.NodeMappings {
		logrus.WithFields(logrus.Fields{
			"role":   mapping.RoleARN,
			"groups": mapping.Groups,
		}).Infof("mapping Node role")
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
		lowercaseNodeMap: make(map[string]config.NodeMapping),
		accountMap:       make(map[string]bool),
		verifier:         token.NewVerifier(c.ClusterID),
		metrics:          createMetrics(),
		nodeNameProvider: NewNodeNameEC2PrivateDNSProvider(c.DefaultEC2DescribeInstancesRoleARN),
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
	for _, m := range c.NodeMappings {
		h.lowercaseNodeMap[strings.ToLower(m.RoleARN)] = m
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
	if nodeMapping, exists := h.lowercaseNodeMap[arnLower]; exists {
		nodeName, err := h.nodeNameProvider.GetNodeName(identity.SessionName)
		if err != nil {
			log.WithError(err).Warn("access denied because node private DNS was not found")
			w.WriteHeader(http.StatusForbidden)
			w.Write(tokenReviewDenyJSON)
			return
		}
		username = nodeName
		groups = nodeMapping.Groups
	} else if roleMapping, exists := h.lowercaseRoleMap[arnLower]; exists {
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

type NodeNameProvider interface {
	// Get a node name from instance ID
	GetNodeName(string) (string, error)
}

type nodeNameEC2PrivateDNSProvider struct {
	sess          *session.Session
	nodeNameCache map[string]string
	lock          sync.Mutex
}

func NewNodeNameEC2PrivateDNSProvider(roleARN string) NodeNameProvider {
	return &nodeNameEC2PrivateDNSProvider{
		sess:          newSession(roleARN),
		nodeNameCache: make(map[string]string),
	}
}

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

func (p *nodeNameEC2PrivateDNSProvider) getPrivateDNSName(id string) (string, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	name, ok := p.nodeNameCache[id]
	if ok {
		return name, nil
	}
	return "", errors.New("instance id not found")
}

func (p *nodeNameEC2PrivateDNSProvider) setPrivateDNSName(id string, privateDNSName string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.nodeNameCache[id] = privateDNSName
}

// getNodeName looks up the private DNS from the EC2 API
// and returns a username for the node matching the format that
// kubelet uses: "system:node:<private-DNS>"
func (p *nodeNameEC2PrivateDNSProvider) GetNodeName(id string) (string, error) {
	privateDNSName, err := p.getPrivateDNSName(id)
	if err == nil {
		return config.NodeNamePrefix + privateDNSName, nil
	}

	// Look up instance from EC2 API
	instanceIds := []*string{&id}
	ec2Service := ec2.New(p.sess)
	output, err := ec2Service.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	})
	if err != nil {
		return "", errors.New(fmt.Sprintf("failed querying private DNS from EC2 API for node %s: %s", id, err.Error()))
	}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				privateDNSName = aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSName(id, privateDNSName)
			}
		}
	}
	if privateDNSName == "" {
		return "", errors.New(fmt.Sprintf("failed to find private DNS Name for node %s", id))
	}
	return config.NodeNamePrefix + privateDNSName, nil
}

func renderTemplate(template string, identity *token.Identity) string {
	// usernames and groups must be a DNS-1123 hostname matching the regex
	// "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
	sessionName := strings.Replace(identity.SessionName, "@", "-", -1)

	template = strings.Replace(template, "{{AccountID}}", identity.AccountID, -1)
	template = strings.Replace(template, "{{SessionName}}", sessionName, -1)
	return template
}
