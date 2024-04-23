package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/synctyped"
	"go.flipt.io/reverst/pkg/protocol"
)

type Config struct {
	Level            Level  `ff:" short=l | long=log              | default=info             | usage: 'debug, info, warn or error'                           "`
	TunnelAddress    string `ff:" short=a | long=tunnel-address   | default='127.0.0.1:7171' | usage: address for accepting tunnelling quic connections      "`
	HTTPAddress      string `ff:" short=s | long=http-address     | default='0.0.0.0:8181'   | usage: address for serving HTTP requests                      "`
	TunnelGroupsPath string `ff:" short=g | long=tunnel-groups    | default='groups.yml'     | usage: path to tunnel groups configuration file               "`
	ServerName       string `ff:" short=n | long=server-name      |                            usage: server name used to identify tunnel via TLS (required) "`
	PrivateKeyPath   string `ff:" short=k | long=private-key-path |                            usage: path to TLS private key PEM file (required)            "`
	CertificatePath  string `ff:" short=c | long=certificate-path |                            usage: path to TLS certificate PEM file (required)            "`

	// ManagementAddress is where reverst hosts introspective APIs for telemetry and debugging etc.
	ManagementAddress string `ff:" long=management-address | usage: HTTP address for managment API "`

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

	return nil
}

// TunnelGroups is a configuration file format for defining the tunnel
// groups served by an instance of then reverst tunnel server.
type TunnelGroups struct {
	Groups map[string]TunnelGroup `json:"groups,omitempty" yaml:"groups,omitempty"`
}

func (g TunnelGroups) Validate() error {
	for _, g := range g.Groups {
		if err := g.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (g TunnelGroups) AuthenticationHandler() (protocol.AuthenticationHandler, error) {
	handlerCache := synctyped.Map[protocol.AuthenticationHandler]{}

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		group, ok := g.Groups[rlr.TunnelGroup]
		if !ok {
			return fmt.Errorf("unknown tunnel group: %q", rlr.TunnelGroup)
		}

		handler, ok := handlerCache.Load(rlr.TunnelGroup)
		if !ok {
			switch group.Authentication.Type {
			case "", "basic":
				handler = auth.HandleBasic(group.Authentication.Username, group.Authentication.Password)
			case "token", "bearer":
				if group.Authentication.Token != "" || group.Authentication.TokenPath != "" {
					token := group.Authentication.Token
					if token == "" {
						tokenBytes, err := os.ReadFile(group.Authentication.TokenPath)
						if err != nil {
							return err
						}

						token = string(tokenBytes)
					}

					handler = auth.HandleBearer(token)
				} else {
					token := group.Authentication.HashedToken
					if token == "" {
						tokenBytes, err := os.ReadFile(group.Authentication.HashedTokenPath)
						if err != nil {
							return err
						}

						token = string(tokenBytes)
					}

					var err error
					handler, err = auth.HandleBearerHashed(token)
					if err != nil {
						return err
					}
				}
			case "insecure":
				handler = protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
					return nil
				})
			default:
				return fmt.Errorf("unknown authentication type: %q", group.Authentication.Type)
			}

			handlerCache.Store(rlr.TunnelGroup, handler)
		}

		return handler.Authenticate(rlr)
	}), nil
}

// TunnelGroup is an instance of a tunnel group which identifies
// the hostnames served by the instances in the group.
type TunnelGroup struct {
	Hosts          []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	Authentication struct {
		Type            string `json:"type" yaml:"type"`
		Username        string `json:"username,omitempty" yaml:"username,omitempty"`
		Password        string `json:"password,omitempty" yaml:"password,omitempty"`
		Token           string `json:"token,omitempty" yaml:"token,omitempty"`
		TokenPath       string `json:"tokenPath,omitempty" yaml:"tokenPath,omitempty"`
		HashedToken     string `json:"hashedToken,omitempty" yaml:"hashedToken,omitempty"`
		HashedTokenPath string `json:"hashedTokenPath,omitempty" yaml:"hashedTokenPath,omitempty"`
	} `json:"authentication,omitempty"`
}

func (g TunnelGroup) Validate() error {
	auth := g.Authentication
	switch auth.Type {
	case "", "basic":
		if auth.Username == "" {
			return errors.New("username must be non-empty string (when auth-type == basic)")
		}

		if auth.Password == "" {
			return errors.New("password must be non-empty string (when auth-type == basic)")
		}
	case "bearer", "token":
		if auth.Token == "" &&
			auth.TokenPath == "" &&
			auth.HashedToken == "" &&
			auth.HashedTokenPath == "" {
			return errors.New("one of token, tokenPath, hashedToken or hashedTokenPath must be non-empty string (when auth-type == bearer)")
		}
	case "insecure":
		slog.Warn("Authentication type insecure has been chosen (requests will not be authenticated)")

		return nil
	default:
		return fmt.Errorf("unknown authentication type: %q", auth.Type)
	}

	return nil
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
