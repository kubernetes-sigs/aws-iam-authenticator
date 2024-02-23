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
	authenticatorMetrics = createMetrics(registerer)
}

func Get() Metrics {
	return authenticatorMetrics
}

// Metrics are handles to the collectors for prometheus for the various metrics we are tracking.
type Metrics struct {
	ConfigMapWatchFailures       prometheus.Counter
	Latency                      *prometheus.HistogramVec
	EC2DescribeInstanceCallCount prometheus.Counter
	StsConnectionFailure         prometheus.Counter
	StsResponses                 *prometheus.CounterVec
	DynamicFileFailures          prometheus.Counter
	StsThrottling                prometheus.Counter
	E2ELatency                   *prometheus.HistogramVec
	DynamicFileEnabled           prometheus.Gauge
	DynamicFileOnly              prometheus.Gauge
}

func createMetrics(reg prometheus.Registerer) Metrics {
	factory := promauto.With(reg)

	return Metrics{
		ConfigMapWatchFailures: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "configmap_watch_failures_total",
				Help:      "EKS Configmap watch failures",
			},
		),
		DynamicFileFailures: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "dynamicfile_failures_total",
				Help:      "Dynamic file failures",
			},
		),
		StsConnectionFailure: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "sts_connection_failures_total",
				Help:      "Sts call could not succeed or timedout",
			},
		),
		StsResponses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "sts_responses_total",
				Help:      "Sts responses with error code label",
			}, []string{"ResponseCode"},
		),
		Latency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: Namespace,
				Name:      "authenticate_latency_seconds",
				Help:      "Authenticate call latency",
			},
			[]string{"result"},
		),
		EC2DescribeInstanceCallCount: factory.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "ec2_describe_instances_calls_total",
				Help:      "Number of EC2 describe instances calls.",
			},
		),
		E2ELatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:      "dynamic_e2e_latency_seconds",
				Namespace: Namespace,
				Help:      "End to end latency in seconds partitioned by type.",
				Buckets:   []float64{1, 3, 5, 10, 15, 20, 30, 60},
			},
			[]string{"type"},
		),
		DynamicFileEnabled: factory.NewGauge(
			prometheus.GaugeOpts{
				Name:      "dynamic_file_enabled",
				Namespace: Namespace,
				Help:      "Dynamic file in backend mode is enabled",
			},
		),
		DynamicFileOnly: factory.NewGauge(
			prometheus.GaugeOpts{
				Name:      "dynamic_file_only",
				Namespace: Namespace,
				Help:      "Only dynamic file in backend mode is enabled",
			},
		),
	}
}
