package config

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/protocol"
)

type Config struct {
	Level            Level  `ff:" short=l | long=log              | default=info             | usage: 'debug, info, warn or error'                           "`
	TunnelAddress    string `ff:" short=a | long=tunnel-address   | default='127.0.0.1:7171' | usage: address for accepting tunnelling quic connections      "`
	HTTPAddress      string `ff:" short=s | long=http-address     | default='127.0.0.1:8181' | usage: address for serving HTTP requests                      "`
	TunnelGroupsPath string `ff:" short=g | long=tunnel-groups    | default='groups.yml'     | usage: path to tunnel groups configuration file               "`
	ServerName       string `ff:" short=n | long=server-name      |                            usage: server name used to identify tunnel via TLS (required) "`
	PrivateKeyPath   string `ff:" short=k | long=private-key-path |                            usage: path to TLS private key PEM file (required)            "`
	CertificatePath  string `ff:" short=c | long=certificate-path |                            usage: path to TLS certificate PEM file (required)            "`

	AuthType string `ff:" long=auth-type | default=basic  | usage: 'basic, bearer or insecure' "`
	Username string `ff:" long=username  |                  usage: 'basic authentication username (required for auth-type=basic)'    "`
	Password string `ff:" long=password  |                  usage: 'basic authentication password (required for auth-type=basic)'    "`
	Token    string `ff:" long=token     |                  usage: 'token authenticaiton credential (required for auth-type=bearer)' "`

	MaxIdleTimeout  time.Duration `ff:" long=max-idle-timeout  | default=1m  | usage: maximum time a connection can be idle "`
	KeepAlivePeriod time.Duration `ff:" long=keep-alive-period | default=30s | usage: period between keep-alive events      "`
}

func (c Config) Validate() error {
	if c.ServerName == "" {
		return errors.New("server-name must be non-empty string")
	}

	if c.PrivateKeyPath == "" {
		return errors.New("private-key-path must be non-empty string")
	}

	if c.CertificatePath == "" {
		return errors.New("certificate-path must be non-empty string")
	}

	switch c.AuthType {
	case "basic":
		if c.Username == "" {
			return errors.New("username must be non-empty string (when auth-type == basic)")
		}

		if c.Password == "" {
			return errors.New("password must be non-empty string (when auth-type == basic)")
		}
	case "token":
		if c.Token == "" {
			return errors.New("token must be non-empty string (when auth-type == bearer)")
		}
	case "insecure":
		slog.Warn("Authentication type insecure has been chosen (requests will not be authenticated)")

		return nil
	default:
		return fmt.Errorf("unknown authentication type: %q", c.AuthType)
	}

	return nil
}

func (c Config) AuthenticationHandler() (protocol.AuthenticationHandler, error) {
	switch c.AuthType {
	case "basic":
		return auth.HandleBasic(c.Username, c.Password), nil
	case "token":
		return auth.HandleBearer(c.Token), nil
	case "insecure":
		return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
			return nil
		}), nil
	default:
		return nil, fmt.Errorf("unknown authentication type: %q", c.AuthType)
	}
}

type Level slog.Level

func (l Level) String() string {
	return slog.Level(l).String()
}

func (l *Level) Set(v string) error {
	level := slog.Level(*l)
	if err := level.UnmarshalText([]byte(v)); err != nil {
		return err
	}

	*l = Level(level)
	return nil
}

// TunnelGroups is a configuration file format for defining the tunnel
// groups served by an instance of then reverst tunnel server.
type TunnelGroups struct {
	Groups map[string]TunnelGroup `json:"groups,omitempty" yaml:"groups,omitempty"`
}

// TunnelGroup is an instance of a tunnel group which identifies
// the hostnames served by the instances in the group.
type TunnelGroup struct {
	Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
}
