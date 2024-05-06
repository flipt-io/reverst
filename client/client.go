package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/pkg/protocol"
	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	// DefaultTLSConfig is the default configuration used for establishing
	// TLS over QUIC.
	DefaultTLSConfig = &tls.Config{
		NextProtos: []string{protocol.Name},
	}
	// DefaultQuicConfig is the default configuration used for establishing
	// QUIC connections.
	DefaultQuicConfig = &quic.Config{
		MaxIdleTimeout:  20 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}

	// DefaultBackoff is the default backoff used when dialing and serving
	// a connection.
	DefaultBackoff = wait.Backoff{
		Steps:    5,
		Duration: 100 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
	}
)

// Server is an alternative HTTP server that dials to a reverst Tunnel server
// and attempts to remotely register itself as a listener.
// Given the connection is established and authorized as a valid listener the
// server switches into serving mode and handles HTTP/3 requests over the connection.
// The Tunnel should forward requests to this connection and any others in the
// same tunnel group. The group is identified via the TLSConfig.ServerName.
type Server struct {
	// TunnelGroup is an identifier for the group in which this server should
	// be registered against on the target tunnel server.
	TunnelGroup string

	// Handler is the root http.Handler of the server instance.
	Handler http.Handler

	// Logger allows the caller to configure a custome *slog.Logger instance.
	// If not defined then Server uses the default instance returned by slog.Default.
	Logger *slog.Logger

	// TLSConfig is used to configure TLS encryption over the Quic connection.
	// See DefaultTLSConfig for the parameters used which this is set to nil.
	TLSConfig *tls.Config

	// QuicConfig is used to configure Quic connections.
	// See DefaultQuicConfig for the parameters used which this is set to nil.
	QuicConfig *quic.Config

	// Authenticator is the Authenticator used to authenticate outbound
	// listener registration requests.
	Authenticator Authenticator

	// OnConnectionReady is called when the server has successfully
	// registered itself with the upstream tunnel server
	OnConnectionReady func(protocol.RegisterListenerResponse)
}

func coallesce[T any](v, d *T) *T {
	if v == nil {
		return d
	}

	return v
}

func (s *Server) getTLSConfig(addr string) (*tls.Config, error) {
	tlsConf := coallesce(s.TLSConfig, DefaultTLSConfig)
	if tlsConf.ServerName == "" {
		// if the TLS ServerName is not explicitly supplied
		// then we will parse the dial address and use the hostname
		// defined on that instead
		url, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}

		tlsConf.ServerName = url.Hostname()
	}

	return tlsConf, nil
}

// DialAndServe dials out to the provided address and attempts to register the server
// as a listener on the remote tunnel group.
func (s *Server) DialAndServe(ctx context.Context, addr string) (err error) {
	attrs := []slog.Attr{slog.String("addr", addr)}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		attrs = []slog.Attr{slog.String("host", host), slog.String("port", port)}
	}

	log := slog.New(coallesce(s.Logger, slog.Default()).Handler().WithAttrs(attrs))
	log.Debug("Dialing address")

	tlsConf, err := s.getTLSConfig(addr)
	if err != nil {
		return err
	}

	quicConf := coallesce(s.QuicConfig, DefaultQuicConfig)

	var lastErr error
	err = wait.ExponentialBackoffWithContext(ctx, DefaultBackoff, func(context.Context) (done bool, err error) {
		err = s.dialAndServe(ctx, log, addr, tlsConf, quicConf)
		if err != nil {
			lastErr = err
			if errors.Is(err, context.Canceled) {
				return false, nil
			}

			// we log out the error under debug as this function will be repeated
			// and hopefully will eventually succeed
			// if not then the last observed error should be returned and logged
			// at a higher log level
			log.Debug("Error while attempting to dial and register", "error", err)

			return false, nil
		}

		return true, nil
	})

	// this signifies that the exponential backoff was exhausted or exceeded a deadline
	// in this situation we simply return the last observed error in the dial and serve attempts
	if wait.Interrupted(err) {
		err = lastErr
	}

	return err
}

func (s *Server) dialAndServe(
	ctx context.Context,
	log *slog.Logger,
	addr string,
	tlsConf *tls.Config,
	quicConf *quic.Config,
) error {
	conn, err := quic.DialAddr(ctx,
		addr,
		tlsConf,
		coallesce(s.QuicConfig, DefaultQuicConfig),
	)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()

		_ = conn.CloseWithError(protocol.ApplicationOK, "")
	}()

	log.Debug("Attempting to register")

	// register server as a listener on remote tunnel
	if err := s.register(conn); err != nil {
		return err
	}

	log.Info("Starting server")

	return (&http3.Server{Handler: s.Handler}).ServeQUICConn(conn)
}

func (s *Server) register(conn quic.Connection) error {
	stream, err := conn.OpenStream()
	if err != nil {
		return fmt.Errorf("accepting stream: %w", err)
	}

	defer stream.Close()

	enc := protocol.NewEncoder[protocol.RegisterListenerRequest](stream)
	defer enc.Close()

	req := &protocol.RegisterListenerRequest{
		Version:     protocol.Version,
		TunnelGroup: s.TunnelGroup,
	}

	auth := defaultAuthenticator
	if s.Authenticator != nil {
		auth = s.Authenticator
	}

	if err := auth.Authenticate(stream.Context(), req); err != nil {
		return fmt.Errorf("registering new connection: %w", err)
	}

	if err := enc.Encode(req); err != nil {
		return fmt.Errorf("encoding register listener request: %w", err)
	}

	dec := protocol.NewDecoder[protocol.RegisterListenerResponse](stream)
	defer dec.Close()

	resp, err := dec.Decode()
	if err != nil {
		return fmt.Errorf("decoding register listener response: %w", err)
	}

	if resp.Code != protocol.CodeOK {
		return fmt.Errorf("unexpected response code: %s", resp.Code)
	}

	if s.OnConnectionReady != nil {
		s.OnConnectionReady(resp)
	}

	return nil
}
