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
	"regexp"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/aws-iam-authenticator/pkg/arn"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"

	"k8s.io/client-go/tools/cache"

	"k8s.io/component-base/featuregate"

	iamauthenticatorv1alpha1 "sigs.k8s.io/aws-iam-authenticator/pkg/apis/iamauthenticator/v1alpha1"
	informers "sigs.k8s.io/aws-iam-authenticator/pkg/generated/informers/externalversions/iamauthenticator/v1alpha1"
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

// Pattern to match EC2 instance IDs
var (
	instanceIDPattern = regexp.MustCompile("^i-(\\w{8}|\\w{17})$")
	dns1123Pattern    = regexp.MustCompile("[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*")
)

// server state (internal)
type handler struct {
	http.ServeMux
	lowercaseRoleMap map[string]config.RoleMapping
	lowercaseUserMap map[string]config.UserMapping
	iamMappingsIndex cache.Indexer
	accountMap       map[string]bool
	verifier         token.Verifier
	metrics          metrics
	ec2Provider      EC2Provider
	featureGates     featuregate.MutableFeatureGate
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

// New the authentication webhook server.
func New(
	cfg config.Config,
	iamMappingInformer informers.IAMIdentityMappingInformer) *Server {
	c := &Server{
		Config:            cfg,
		iamMappingsSynced: iamMappingInformer.Informer().HasSynced,
		iamMappingsIndex:  iamMappingInformer.Informer().GetIndexer(),
	}

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

	listenAddr := fmt.Sprintf("%s:%d", c.Address, c.HostPort)
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

	// create a logrus logger for HTTP error logs
	errLog := logrus.WithField("http", "error").Writer()
	defer errLog.Close()

	logrus.Infof("listening on %s", listenURL)
	logrus.Infof("reconfigure your apiserver with `--authentication-token-webhook-config-file=%s` to enable (assuming default hostPath mounts)", c.GenerateKubeconfigPath)
	c.httpServer = http.Server{
		ErrorLog: log.New(errLog, "", 0),
		Handler:  c.getHandler(),
	}
	c.listener = listener
	return c
}

// Run will run the server closing the connection if there is a struct on the channel
func (c *Server) Run(stopCh <-chan struct{}) {
	defer c.listener.Close()

	if c.FeatureGates.Enabled(config.IAMIdentityMappingCRD) {
		if ok := cache.WaitForCacheSync(stopCh, c.iamMappingsSynced); !ok {
			logrus.Fatal("failed to wait for caches to sync in server")
		}
	}

	if err := c.httpServer.Serve(c.listener); err != nil {
		logrus.WithError(err).Fatal("http server exited")
	}
}

func (c *Server) getHandler() *handler {
	h := &handler{
		lowercaseRoleMap: make(map[string]config.RoleMapping),
		lowercaseUserMap: make(map[string]config.UserMapping),
		iamMappingsIndex: c.iamMappingsIndex,
		accountMap:       make(map[string]bool),
		verifier:         token.NewVerifier(c.ClusterID),
		metrics:          createMetrics(),
		ec2Provider:      newEC2Provider(c.ServerEC2DescribeInstancesRoleARN),
		featureGates:     c.FeatureGates,
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

	log.WithFields(logrus.Fields{
		"arn":       identity.ARN,
		"accountid": identity.AccountID,
		"userid":    identity.UserID,
		"session":   identity.SessionName,
	}).Info("STS response")

	// look up the ARN in each of our mappings to fill in the username and groups
	log = log.WithField("arn", identity.CanonicalARN)

	username, groups, err := h.doMapping(identity)
	if err != nil {
		h.metrics.latency.WithLabelValues(metricUnknown).Observe(duration(start))
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	// use a prefixed UID that includes the AWS account ID and AWS user ID ("AROAAAAAAAAAAAAAAAAAA")
	uid := fmt.Sprintf("aws-iam-authenticator:%s:%s", identity.AccountID, identity.UserID)

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

func (h *handler) doMapping(identity *token.Identity) (string, []string, error) {
	arnLower := strings.ToLower(identity.CanonicalARN)

	// IAMIdentityMappingCRD feature gate will only us the CRD implementation to validate users
	if h.featureGates.Enabled(config.IAMIdentityMappingCRD) {
		var iamidentity *iamauthenticatorv1alpha1.IAMIdentityMapping
		var ok bool
		objects, err := h.iamMappingsIndex.ByIndex("canonicalARN", arnLower)
		if err != nil {
			return "", nil, fmt.Errorf("ARN is not in the index: %s (lowercased from %s)", arnLower, identity.CanonicalARN)
		}

		if len(objects) > 0 {
			for _, obj := range objects {
				iamidentity, ok = obj.(*iamauthenticatorv1alpha1.IAMIdentityMapping)
				if !ok {
					continue
				}
			}

			if iamidentity != nil {
				username, err := h.renderTemplate(iamidentity.Spec.Username, identity)
				if err != nil {
					return "", nil, fmt.Errorf("failed mapping username: %s", err.Error())
				}

				groups := []string{}
				for _, groupPattern := range iamidentity.Spec.Groups {
					group, err := h.renderTemplate(groupPattern, identity)
					if err != nil {
						return "", nil, fmt.Errorf("failed mapping group: %s", err.Error())
					}
					groups = append(groups, group)
				}

				return username, groups, nil
			}
		}
	} else {
		if roleMapping, exists := h.lowercaseRoleMap[arnLower]; exists {
			username, err := h.renderTemplate(roleMapping.Username, identity)
			if err != nil {
				return "", nil, fmt.Errorf("failed mapping username: %s", err.Error())
			}
			groups := []string{}
			for _, groupPattern := range roleMapping.Groups {
				group, err := h.renderTemplate(groupPattern, identity)
				if err != nil {
					return "", nil, fmt.Errorf("failed mapping group: %s", err.Error())
				}
				groups = append(groups, group)
			}
			return username, groups, nil
		}
		if userMapping, exists := h.lowercaseUserMap[arnLower]; exists {
			return userMapping.Username, userMapping.Groups, nil
		}
	}

	if _, exists := h.accountMap[identity.AccountID]; exists {
		return identity.CanonicalARN, []string{}, nil
	}
	return "", nil, fmt.Errorf("ARN is not mapped: %s (lowercased from %s)", arnLower, identity.CanonicalARN)
}

func (h *handler) renderTemplate(template string, identity *token.Identity) (string, error) {
	// Private DNS requires EC2 API call
	if strings.Contains(template, "{{EC2PrivateDNSName}}") {
		if !instanceIDPattern.MatchString(identity.SessionName) {
			return "", fmt.Errorf("SessionName did not contain an instance id")
		}
		privateDNSName, err := h.ec2Provider.getPrivateDNSName(identity.SessionName)
		if err != nil {
			return "", err
		}
		template = strings.Replace(template, "{{EC2PrivateDNSName}}", privateDNSName, -1)
	}

	template = strings.Replace(template, "{{AccountID}}", identity.AccountID, -1)

	// usernames and groups must be a DNS-1123 hostname matching the regex
	// "[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
	sessionName := strings.Replace(identity.SessionName, "@", "-", -1)
	template = strings.Replace(template, "{{SessionName}}", sessionName, -1)
	if !dns1123Pattern.MatchString(template) {
		return "", fmt.Errorf("username or group is not a DNS-1123 hostname")
	}

	return template, nil
}

// EC2Provider configures a DNS resolving function for nodes
type EC2Provider interface {
	// Get a node name from instance ID
	getPrivateDNSName(string) (string, error)
}

type ec2ProviderImpl struct {
	ec2             ec2iface.EC2API
	privateDNSCache map[string]string
	lock            sync.Mutex
}

func newEC2Provider(roleARN string) EC2Provider {
	return &ec2ProviderImpl{
		ec2:             ec2.New(newSession(roleARN)),
		privateDNSCache: make(map[string]string),
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

func (p *ec2ProviderImpl) getPrivateDNSNameCache(id string) (string, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	name, ok := p.privateDNSCache[id]
	if ok {
		return name, nil
	}
	return "", errors.New("instance id not found")
}

func (p *ec2ProviderImpl) setPrivateDNSNameCache(id string, privateDNSName string) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.privateDNSCache[id] = privateDNSName
}

// GetPrivateDNS looks up the private DNS from the EC2 API
func (p *ec2ProviderImpl) getPrivateDNSName(id string) (string, error) {
	privateDNSName, err := p.getPrivateDNSNameCache(id)
	if err == nil {
		return privateDNSName, nil
	}

	// Look up instance from EC2 API
	output, err := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{id}),
	})
	if err != nil {
		return "", fmt.Errorf("failed querying private DNS from EC2 API for node %s: %s", id, err.Error())
	}
	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				privateDNSName = aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSNameCache(id, privateDNSName)
			}
		}
	}
	if privateDNSName == "" {
		return "", fmt.Errorf("failed to find node %s", id)
	}
	return privateDNSName, nil
}
