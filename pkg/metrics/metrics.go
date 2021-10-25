package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	Namespace = "aws_iam_authenticator"
	Malformed = "malformed_request"
	Invalid   = "invalid_token"
	STSError  = "sts_error"
	Unknown   = "uknown_user"
	Success   = "success"
)

var authenticatorMetrics Metrics

func InitMetrics(registerer prometheus.Registerer) {
	authenticatorMetrics = CreateMetrics(registerer)
}

func Get() Metrics {
	return authenticatorMetrics
}

// Metrics are handles to the collectors for prometheus for the various metrics we are tracking.
type Metrics struct {
	ConfigMapWatchFailures prometheus.Counter
	Latency                *prometheus.HistogramVec
	AWSAPILatency          *prometheus.HistogramVec
	AWSAPIErrors           *prometheus.CounterVec
	AWSAPIThrottles        *prometheus.CounterVec
}

func CreateMetrics(reg prometheus.Registerer) Metrics {
	factory := promauto.With(reg)

	return Metrics{
		ConfigMapWatchFailures: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "configmap_watch_failures",
				Help:      "EKS Configmap watch failures",
			},
		),
		Latency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "authenticate_latency_seconds",
				Help:      "Authenticate call latency",
			},
			[]string{"result"},
		),
		AWSAPILatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "cloudprovider_aws_api_request_duration_seconds",
				Help: "Latency of AWS API calls",
			},
			[]string{"request"},
		),
		AWSAPIErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cloudprovider_aws_api_request_errors",
				Help: "AWS API errors",
			},
			[]string{"request"},
		),
		AWSAPIThrottles: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cloudprovider_aws_api_throttled_requests_total",
				Help: "AWS API throttled requests",
			},
			[]string{"operation_name"},
		),
	}
}

func RecordAWSMetric(actionName string, timeTaken float64, err error) {
	if err != nil {
		authenticatorMetrics.AWSAPIErrors.With(prometheus.Labels{"request": actionName}).Inc()
	} else {
		authenticatorMetrics.AWSAPILatency.With(prometheus.Labels{"request": actionName}).Observe(timeTaken)
	}
}

func RecordAWSThrottlesMetric(operation string) {
	authenticatorMetrics.AWSAPIThrottles.With(prometheus.Labels{"operation_name": operation}).Inc()
}
