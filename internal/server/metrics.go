package server

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	prom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const (
	meterName = "go.flipt.io/reverst"

	namespace = "reverst"

	tunnelGroupSubsystem = "tunnel_group"
	proxySubsystem       = "tunnel_group_proxy"
)

var (
	tunnelGroupKey = attribute.Key("tunnel_group")
	hostKey        = attribute.Key("host")
	statusKey      = attribute.Key("status")
	errorKey       = attribute.Key("error")
)

type metrics struct {
	metric.Meter

	tunnelGroupRegistrationsTotal metric.Int64Counter
	proxyRequestsHandledTotal     metric.Int64Counter
	proxyRequestsLatency          metric.Float64Histogram
}

func newMetrics(address string) (m metrics, err error) {
	m.Meter = noop.NewMeterProvider().Meter(meterName)
	if address != "" {
		exporter, err := prom.New()
		if err != nil {
			log.Fatal(err)
		}

		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
		m.Meter = provider.Meter(meterName)
	}

	m.tunnelGroupRegistrationsTotal, err = m.Meter.Int64Counter(
		prometheus.BuildFQName(namespace, tunnelGroupSubsystem, "registrations_total"),
		metric.WithDescription("Total number of registration attempts handled by tunnel group and status code"),
	)
	if err != nil {
		return
	}

	m.proxyRequestsHandledTotal, err = m.Meter.Int64Counter(
		prometheus.BuildFQName(namespace, proxySubsystem, "requests_total"),
		metric.WithDescription("Total number of requests handled by host and response code"),
	)
	if err != nil {
		return
	}

	m.proxyRequestsLatency, err = m.Meter.Float64Histogram(
		prometheus.BuildFQName(namespace, proxySubsystem, "requests_latency"),
		metric.WithDescription("Latency of requests per host and response code"),
		metric.WithUnit("ms"),
	)

	return
}
