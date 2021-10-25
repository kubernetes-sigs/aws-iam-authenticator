package cloud

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg"
	"sigs.k8s.io/aws-iam-authenticator/pkg/httputil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

type Cloud struct {
	EC2 ec2iface.EC2API
}

type AwsOpts struct {
	RoleARN string
	QPS     int
	Burst   int
}

// NewCloud returns a new instance of AWS cloud
// It panics if session is invalid
func NewCloud(opts AwsOpts) (*Cloud, error) {
	ec2API := ec2.New(newSession(opts))

	ec2API.Handlers.AfterRetry.PushFrontNamed(request.NamedHandler{
		Name: "recordThrottledRequestsHandler",
		Fn:   recordThrottledRequestsHandler,
	})
	ec2API.Handlers.Complete.PushFrontNamed(request.NamedHandler{
		Name: "recordRequestsHandler",
		Fn:   recordRequestsHandler,
	})

	return &Cloud{
		EC2: ec2API,
	}, nil
}

// newSession configures a session for the authenticator server.
// Credentials loaded from SDK's default credential chain, such as
// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
// Role.
func newSession(opts AwsOpts) *session.Session {
	rateLimitedClient, err := httputil.NewRateLimitedClient(opts.QPS, opts.Burst)
	if err != nil {
		logrus.WithError(err).Fatal("Failed creating rate limited client.")
	}
	cfg := aws.NewConfig().WithHTTPClient(rateLimitedClient).WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)
	sess := session.Must(session.NewSession(cfg))

	sess.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "authenticatorUserAgent",
		Fn: request.MakeAddToUserAgentHandler(
			pkg.AppName, pkg.Version, "server"),
	})

	if aws.StringValue(sess.Config.Region) == "" {
		ec2metadata := ec2metadata.New(sess)
		regionFound, err := ec2metadata.Region()
		if err != nil {
			logrus.WithError(err).Fatal("Region not found in shared credentials, environment variable, or instance metadata.")
		}
		sess.Config.Region = aws.String(regionFound)
	}

	if opts.RoleARN != "" {
		ap := &stscreds.AssumeRoleProvider{
			Client:   sts.New(sess),
			RoleARN:  opts.RoleARN,
			Duration: time.Duration(60) * time.Minute,
		}

		sess.Config.Credentials = credentials.NewCredentials(ap)
	}
	return sess
}

// RecordRequestsComplete is added to the Complete chain; called after any request
func recordRequestsHandler(r *request.Request) {
	metrics.RecordAWSMetric(operationName(r), time.Since(r.Time).Seconds(), r.Error)
}

// RecordThrottlesAfterRetry is added to the AfterRetry chain; called after any error
func recordThrottledRequestsHandler(r *request.Request) {
	if r.IsErrorThrottle() {
		metrics.RecordAWSThrottlesMetric(operationName(r))
		logrus.Warningf("Got RequestLimitExceeded error on AWS request (%s)",
			describeRequest(r))
	}
}

// Return the operation name, for use in log messages and metrics
func operationName(r *request.Request) string {
	name := "N/A"
	if r.Operation != nil {
		name = r.Operation.Name
	}
	return name
}

// Return a user-friendly string describing the request, for use in log messages
func describeRequest(r *request.Request) string {
	service := r.ClientInfo.ServiceName
	return service + "::" + operationName(r)
}
