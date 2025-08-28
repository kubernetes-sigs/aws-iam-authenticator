package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	Namespace     = "aws_iam_authenticator"
	Malformed     = "malformed_request"
	Invalid       = "invalid_token"
	STSError      = "sts_error"
	STSThrottling = "sts_throttling"
	Unknown       = "uknown_user"
	Success       = "success"
)

var authenticatorMetrics Metrics
var initialized bool

func InitMetrics(registerer prometheus.Registerer) {
	authenticatorMetrics = createMetrics(registerer)
	initialized = true
}

// Initialized returns true if InitMetrics() has been called, and false
// otherwise.
func Initialized() bool {
	return initialized
}

func Get() Metrics {
	return authenticatorMetrics
}

// Metrics are handles to the collectors for prometheus for the various metrics we are tracking.
type Metrics struct {
	ConfigMapWatchFailures       prometheus.Counter
	Latency                      *prometheus.HistogramVec
	EC2DescribeInstanceCallCount prometheus.Counter
	StsConnectionFailure         *prometheus.CounterVec
	StsResponses                 *prometheus.CounterVec
	StsDisableRegionRequests     prometheus.Counter
	DynamicFileFailures          prometheus.Counter
	StsThrottling                *prometheus.CounterVec
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
		StsConnectionFailure: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "sts_connection_failures_total",
				Help:      "Sts call could not succeed or timedout",
			}, []string{"StsRegion"},
		),
		StsThrottling: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "sts_throttling_total",
				Help:      "Sts call got throttled",
			}, []string{"StsRegion"},
		),
		StsResponses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "sts_responses_total",
				Help:      "Sts responses with error code label",
			}, []string{"ResponseCode", "StsRegion"},
		),
		StsDisableRegionRequests: factory.NewCounter(
			prometheus.CounterOpts{
				Name:      "sts_disabled_region_call",
				Namespace: Namespace,
				Help:      "Number of STS calls made to regions that are disabled / disabling",
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
