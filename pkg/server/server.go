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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/heptiolabs/kubernetes-aws-authenticator/pkg/config"
	"github.com/heptiolabs/kubernetes-aws-authenticator/pkg/token"

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
	clusterID        string
	lowercaseRoleMap map[string]config.StaticRoleMapping
}

// New creates a new server from a config
func New(config config.Config) *Server {
	return &Server{
		Config: config,
	}
}

// Run the authentication webhook server.
func (c *Server) Run() {
	for _, mapping := range c.StaticRoleMappings {
		logrus.WithFields(logrus.Fields{
			"role":     mapping.RoleARN,
			"username": mapping.Username,
			"groups":   mapping.Groups,
		}).Infof("statically mapping IAM role")
	}

	// we always listen on localhost (and run with host networking)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", c.LocalhostPort)
	listenURL := fmt.Sprintf("https://%s/authenticate", listenAddr)

	cert, err := c.LoadExistingCertificate()
	if err != nil {
		logrus.WithError(err).Fatalf("could not load/generate a certificate")
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
		clusterID:        c.ClusterID,
		lowercaseRoleMap: make(map[string]config.StaticRoleMapping),
	}
	for _, m := range c.StaticRoleMappings {
		h.lowercaseRoleMap[strings.ToLower(m.RoleARN)] = m
	}

	h.HandleFunc("/authenticate", h.authenticateEndpoint)
	return h
}

func (h *handler) authenticateEndpoint(w http.ResponseWriter, req *http.Request) {
	log := logrus.WithFields(logrus.Fields{
		"path":   req.URL.Path,
		"client": req.RemoteAddr,
		"method": req.Method,
	})

	if req.Method != http.MethodPost {
		log.Error("unexpected request method")
		http.Error(w, "expected POST", http.StatusMethodNotAllowed)
		return
	}
	if req.Body == nil {
		log.Error("empty request body")
		http.Error(w, "expected a request body", http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	var tokenReview authenticationv1beta1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&tokenReview); err != nil {
		log.WithError(err).Error("could not parse request body")
		http.Error(w, "expected a request body to be a TokenReview", http.StatusBadRequest)
		return
	}

	// TODO: rate limit here so we can't be tricked into spamming AWS

	// all responses from here down have JSON bodies
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	// if the token is invalid, reject with a 403
	roleARN, err := token.Verify(tokenReview.Spec.Token, h.clusterID)
	if err != nil {
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	// if the token has a valid signature but the role is not mapped,
	// deny with a 403 but print a more useful log message
	roleARNLower := strings.ToLower(roleARN)
	mapping, exists := h.lowercaseRoleMap[roleARNLower]
	if !exists {
		log.WithField("role", roleARN).Warn("access denied because role is not mapped")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	// use a prefixed 128 bit hash of the lowercase role ARN as a UID
	// (this is meant to be opaque but uniquely identity the user over time)
	hash := sha256.Sum256([]byte(roleARNLower))
	uid := fmt.Sprintf("kubernetes-aws-authenticator:%s", hex.EncodeToString(hash[:16]))

	// the token is valid and the role is mapped, return success!
	log.WithFields(logrus.Fields{
		"username": mapping.Username,
		"uid":      uid,
		"groups":   mapping.Groups,
	}).Info("access granted")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: mapping.Username,
				UID:      uid,
				Groups:   mapping.Groups,
			},
		},
	})
}
