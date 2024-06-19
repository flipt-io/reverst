package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/pkg/protocol"
)

var (
	kSource    *k8sSource
	kSourceErr error
	once       sync.Once
)

func getK8sSource(ctx context.Context) (*k8sSource, error) {
	once.Do(func() {
		kSource, kSourceErr = newK8sSource(ctx)
	})

	return kSource, kSourceErr
}

type Config struct {
	Level             Level  `ff:" short=l | long=log              | default=info             | usage: 'debug, info, warn or error'                           "`
	TunnelAddress     string `ff:" short=a | long=tunnel-address   | default='127.0.0.1:7171' | usage: address for accepting tunnelling quic connections      "`
	HTTPAddress       string `ff:" short=s | long=http-address     | default='0.0.0.0:8181'   | usage: address for serving HTTP requests                      "`
	ServerName        string `ff:" short=n | long=server-name      |                            usage: server name used to identify tunnel via TLS (required) "`
	PrivateKeyPath    string `ff:" short=k | long=private-key-path |                            usage: path to TLS private key PEM file (required)            "`
	CertificatePath   string `ff:" short=c | long=certificate-path |                            usage: path to TLS certificate PEM file (required)            "`
	TunnelGroups      string `ff:" short=g | long=tunnel-groups    | default='groups.yml'     | usage: path to file or k8s configmap identifier               "`
	WatchTunnelGroups bool   `ff:" short=w | long=watch-groups     | default=false            | usage: watch tunnel groups sources for updates "`

	// ManagementAddress is where reverst hosts introspective APIs for telemetry and debugging etc.
	ManagementAddress string `ff:" long=management-address | usage: HTTP address for management API "`

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

func (c *Config) SubscribeTunnelGroups(ctx context.Context, ch chan<- *TunnelGroups) error {
	u, err := url.Parse(c.TunnelGroups)
	if err != nil {
		return err
	}

	switch u.Scheme {
	case "", "file":
		return watchFSNotify(ctx, ch, filepath.Join(u.Host, u.Path), c.WatchTunnelGroups)
	case "k8s":
		if u.Host == "configmap" {
			ns, name, key, err := k8sObjectNamespaceNameKey(u.Path)
			if err != nil {
				return fmt.Errorf("unexpected k8s configmap path: %w", err)
			}

			source, err := getK8sSource(ctx)
			if err != nil {
				return err
			}

			return source.watchConfigMap(ctx, ch, ns, name, key)
		}

		return fmt.Errorf("unsupported k8s resource: %q (expected [configmap])", u.Host)
	}

	return fmt.Errorf("unexpected tunnel group scheme: %q", c.TunnelGroups)
}

// TunnelGroups is a configuration file format for defining the tunnel
// groups served by an instance of then reverst tunnel server.
type TunnelGroups struct {
	Groups map[string]TunnelGroup `json:"groups,omitempty" yaml:"groups,omitempty"`
}

func (g TunnelGroups) Validate(ctx context.Context) error {
	for _, g := range g.Groups {
		if err := g.Validate(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (g TunnelGroups) AuthenticationHandler() protocol.AuthenticationHandler {
	handlers := map[string]protocol.AuthenticationHandler{}
	for name, group := range g.Groups {
		handler := auth.Authenticator{}

		if basic := group.Authentication.Basic; basic != nil {
			scheme := basic.Scheme
			if scheme == "" {
				scheme = "Basic"
			}

			handler[scheme] = auth.HandleBasic(basic.Username, basic.Password)
		}

		if bearer := group.Authentication.Bearer; bearer != nil {
			scheme := bearer.Scheme
			if scheme == "" {
				scheme = "Bearer"
			}

			handler[scheme] = auth.HandleBearerSource(bearer.source)
		}

		if external := group.Authentication.External; external != nil {
			scheme := external.Scheme
			if scheme == "" {
				scheme = "Bearer"
			}

			handler[scheme] = auth.HandleExternalAuthorizer(external.Endpoint)
		}

		handlers[name] = handler
	}

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		handler, ok := handlers[rlr.TunnelGroup]
		if !ok {
			return fmt.Errorf("unknown tunnel group: %q", rlr.TunnelGroup)
		}

		return handler.Authenticate(rlr)
	})
}

// TunnelGroup is an instance of a tunnel group which identifies
// the hostnames served by the instances in the group.
type TunnelGroup struct {
	Hosts          []string                  `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	Authentication TunnelGroupAuthentication `json:"authentication,omitempty" yaml:"authentication,omitempty"`
}

type TunnelGroupAuthentication struct {
	Basic    *AuthenticationBasic    `json:"basic,omitempty" yaml:"basic,omitempty"`
	Bearer   *AuthenticationBearer   `json:"bearer,omitempty" yaml:"bearer,omitempty"`
	External *AuthenticationExternal `json:"external,omitempty" yaml:"external,omitempty"`
}

type AuthenticationBasic struct {
	Scheme   string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

func (a *AuthenticationBasic) scheme() string { return a.Scheme }

func (a *AuthenticationBasic) Validate(context.Context) error {
	if a == nil {
		return nil
	}

	if a.Scheme == "" {
		a.Scheme = "Basic"
	}

	if a.Username == "" {
		return errors.New("basic: username must be non-empty string")
	}

	if a.Password == "" {
		return errors.New("basic: password must be non-empty string")
	}

	return nil
}

type AuthenticationBearer struct {
	Scheme          string            `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Token           string            `json:"token,omitempty" yaml:"token,omitempty"`
	TokenPath       string            `json:"tokenPath,omitempty" yaml:"tokenPath,omitempty"`
	HashedToken     string            `json:"hashedToken,omitempty" yaml:"hashedToken,omitempty"`
	HashedTokenPath string            `json:"hashedTokenPath,omitempty" yaml:"hashedTokenPath,omitempty"`
	source          auth.BearerSource `json:"-" yaml:"-"`
}

func (a *AuthenticationBearer) scheme() string { return a.Scheme }

func (a *AuthenticationBearer) Validate(ctx context.Context) (err error) {
	if a == nil {
		return nil
	}

	if a.Scheme == "" {
		a.Scheme = "Bearer"
	}

	var (
		token  []byte
		path   string
		hashed bool
	)

	switch {
	case a.Token != "":
		token = []byte(a.Token)
	case a.TokenPath != "":
		path = a.TokenPath
	case a.HashedToken != "":
		token = []byte(a.HashedToken)
		hashed = true
	case a.HashedTokenPath != "":
		path = a.HashedTokenPath
		hashed = true
	default:
		return errors.New("bearer: one of token, tokenPath, hashedToken or hashedTokenPath must be non-empty string")
	}

	setStaticTokenSource := func(token []byte) (err error) {
		if !hashed {
			a.source = auth.StaticBearerSource(token)
			return
		}

		a.source, err = auth.HashedStaticBearerSource(token)
		return err
	}

	if len(token) == 0 {
		return setStaticTokenSource(token)
	}

	u, err := url.Parse(path)
	if err != nil {
		return err
	}

	// otherwise, assume the token has been defined at some path
	switch u.Scheme {
	case "", "file":
		token, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("bearer: reading token path %q: %w", path, err)
		}

		return setStaticTokenSource(token)
	case "k8s":
		if u.Host == "secret" {
			ns, name, key, err := k8sObjectNamespaceNameKey(u.Path)
			if err != nil {
				return fmt.Errorf("unexpected k8s secret path: %w", err)
			}

			source, err := getK8sSource(ctx)
			if err != nil {
				return err
			}

			a.source, err = source.newSecretBearerSource(ctx, ns, name, key, true)
			if err != nil {
				return err
			}

			return nil
		}

		return fmt.Errorf("unsupported k8s resource: %q (expected [secret])", u.Host)
	default:
		return fmt.Errorf("unsupported path scheme: %q (expected one of [file k8s])", u.Scheme)
	}
}

type AuthenticationExternal struct {
	Scheme   string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
}

func (a *AuthenticationExternal) scheme() string { return a.Scheme }

func (a *AuthenticationExternal) Validate(context.Context) error {
	if a == nil {
		return nil
	}

	if a.Scheme == "" {
		a.Scheme = "Bearer"
	}

	if a.Endpoint == "" {
		return errors.New("external: endpoint must be non-empty string")
	}

	if _, err := url.Parse(a.Endpoint); err != nil {
		return fmt.Errorf("external: parsing endpoint as URL: %w", err)
	}

	return nil
}

func (g TunnelGroup) Validate(ctx context.Context) error {
	auth := g.Authentication
	if auth.Basic == nil && auth.Bearer == nil && auth.External == nil {
		slog.Warn("No authentication has been configured for tunnel (insecure)")
	}

	schemes := map[string]struct{}{}
	for _, s := range []validator{auth.Basic, auth.Bearer, auth.External} {
		// it is not enough to do a simple == nil check here because of how Go
		// represents variables of interface types as a tuple of concrete type
		// and its value under the hood.
		// we have to use the reflect package to assert that the value is nil
		// and to ignore the fact that each validator implementation has a different
		// yet present concrete type.
		if reflect.ValueOf(s).IsNil() {
			continue
		}

		if err := s.Validate(ctx); err != nil {
			return err
		}

		if _, ok := schemes[s.scheme()]; ok {
			return fmt.Errorf("only one authentication strategy per scheme allowed: %q has duplicates", s.scheme())
		}

		schemes[s.scheme()] = struct{}{}
	}

	return nil
}

type validator interface {
	scheme() string
	Validate(context.Context) error
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

func k8sObjectNamespaceNameKey(path string) (namespace, name, key string, err error) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(parts) < 3 {
		err = fmt.Errorf("expected path form [namespace]/[name]/[key] found: %q", path)
		return
	}

	return parts[0], parts[1], parts[2], nil
}
