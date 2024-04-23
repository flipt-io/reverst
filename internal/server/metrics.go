package server

import "go.opentelemetry.io/otel/attribute"

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
)
