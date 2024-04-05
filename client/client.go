package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/pkg/protocol"
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
)

// Server is an alternative HTTP server that dials to a reverst Tunnel server
// and attempts to register itself as a listener.
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

	conn quic.Connection
}

func coallesce[T any](v, d *T) *T {
	if v == nil {
		return d
	}

	return v
}

// DialAndServe dials out to the provided address and attempts to register the server
// as a listener on the remote tunnel group.
func (s *Server) DialAndServe(ctx context.Context, addr string) (err error) {
	if s.conn != nil {
		return errors.New("server already running")
	}

	log := coallesce(s.Logger, slog.Default()).With("addr", addr)
	log.Debug("Dialing address")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tlsConf := coallesce(s.TLSConfig, DefaultTLSConfig)
	if tlsConf.ServerName == "" {
		// if the TLS ServerName is not explicitly supplied
		// then we will parse the dial address and use the hostname
		// defined on that instead
		url, err := url.Parse(addr)
		if err != nil {
			return err
		}

		tlsConf.ServerName = url.Hostname()
	}

	s.conn, err = quic.DialAddr(ctx,
		addr,
		tlsConf,
		coallesce(s.QuicConfig, DefaultQuicConfig),
	)
	if err != nil {
		return err
	}

	defer func() {
		if s.conn != nil {
			s.conn.CloseWithError(0, "")
			s.conn = nil
		}
	}()

	log.Debug("Attempting to register")

	// register server as a listener on remote tunnel
	if err := s.register(); err != nil {
		return err
	}

	log.Info("Starting server")

	// begin serving HTTP requests
	if err := (&http3.Server{Handler: s.Handler}).ServeQUICConn(s.conn); err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}

		var aerr *quic.ApplicationError
		if errors.As(err, &aerr) {
			if aerr.ErrorCode == 0x0 {
				return nil
			}
		}
	}

	return nil
}

func (s *Server) register() error {
	stream, err := s.conn.OpenStream()
	if err != nil {
		return fmt.Errorf("accepting stream: %w", err)
	}

	defer stream.Close()

	enc := protocol.NewEncoder[protocol.RegisterListenerRequest](stream)
	defer enc.Close()

	req := &protocol.RegisterListenerRequest{
		Version:     protocol.Version,
		TunnelGroup: s.TLSConfig.ServerName,
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

func (s *Server) Close() error {
	if s.conn == nil {
		return nil
	}

	defer func() {
		s.conn = nil
	}()

	return s.conn.CloseWithError(0, "")
}
