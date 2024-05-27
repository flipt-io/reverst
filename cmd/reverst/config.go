package main

import (
	"errors"
	"time"

	"go.flipt.io/reverst/internal/config"
)

type Config struct {
	Level              config.Level `ff:" short=l | long=log            | default=info             | usage: 'debug, info, warn or error'                           "`
	TunnelAddress      string       `ff:" short=a | long=tunnel-address | default='127.0.0.1:7171' | usage: address for accepting tunnelling quic connections      "`
	ServerName         string       `ff:" short=n | long=server-name    |                            usage: server name used to identify tunnel via TLS (required) "`
	TunnelGroup        string       `ff:" short=g | long=tunnel-group   |                            usage: tunnel group to join (defaults to server name)         "`
	CACertificatePath  string       `ff:" short=c | long=cacert-path    |                            usage: path to TLS CA certificate PEM file                    "`
	InsecureSkipVerify bool         `ff:"         | long=insecure       | default=false            | usage: skip TLS certficate verification                       "`

	Username string `ff:" long=username | usage: username for basic authentication "`
	Password string `ff:" long=password | usage: password for basic authentication "`
	Token    string `ff:" long=token    | usage: token for bearer authentication "`
	Scheme   string `ff:" long=scheme   | usage: optionally override auth scheme "`

	MaxIdleTimeout  time.Duration `ff:" long=max-idle-timeout  | default=1m  | usage: maximum time a connection can be idle "`
	KeepAlivePeriod time.Duration `ff:" long=keep-alive-period | default=30s | usage: period between keep-alive events      "`
}

func (c Config) Validate() error {
	if c.ServerName == "" {
		return errors.New("server-name must be non-empty string")
	}

	return nil
}
