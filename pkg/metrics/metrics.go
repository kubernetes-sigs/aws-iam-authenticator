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
	}
}
