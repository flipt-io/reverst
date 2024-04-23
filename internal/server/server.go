package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/roundrobbin"
	"go.flipt.io/reverst/pkg/protocol"
	"gopkg.in/yaml.v2"
)

type Server struct {
	conf    config.Config
	handler protocol.AuthenticationHandler

	// trippers maps tunnel group identifiers onto roundRobbinTripper instances
	trippers map[string]*roundRobbinTripper
	// clients maps host names onto target clients
	clients map[string]*http.Client
}

// New constructs and configures a new reverst Server.
func New(conf config.Config) (*Server, error) {
	fi, err := os.Open(conf.TunnelGroupsPath)
	if err != nil {
		return nil, fmt.Errorf("initializing server: %w", err)
	}

	defer fi.Close()

	var groups config.TunnelGroups
	if err := yaml.NewDecoder(fi).Decode(&groups); err != nil {
		return nil, fmt.Errorf("initializing server: %w", err)
	}

	if err := groups.Validate(); err != nil {
		return nil, fmt.Errorf("validating tunnel groups: %w", err)
	}

	handler, err := groups.AuthenticationHandler()
	if err != nil {
		return nil, fmt.Errorf("initializing server: %w", err)
	}

	s := &Server{
		conf:     conf,
		handler:  handler,
		trippers: map[string]*roundRobbinTripper{},
		clients:  map[string]*http.Client{},
	}

	for name, group := range groups.Groups {
		slog.Debug("Registering tunnel group", "name", name, "hosts", group.Hosts)

		tripper := &roundRobbinTripper{}
		s.trippers[name] = tripper

		client := &http.Client{
			Transport: tripper,
		}

		for _, host := range group.Hosts {
			s.clients[host] = client
		}
	}

	return s, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsCert, err := tls.LoadX509KeyPair(s.conf.CertificatePath, s.conf.PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{protocol.Name},
		ServerName:   s.conf.ServerName,
	}

	listener, err := quic.ListenAddrEarly(s.conf.TunnelAddress, tlsConfig, &quic.Config{
		MaxIdleTimeout:  s.conf.KeepAlivePeriod,
		KeepAlivePeriod: s.conf.MaxIdleTimeout,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	httpServer := &http.Server{
		Addr:    s.conf.HTTPAddress,
		Handler: s,
	}

	go func() {
		<-ctx.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		httpServer.Shutdown(ctx)
	}()

	slog.Info("QUIC tunnel listener starting...", "addr", s.conf.TunnelAddress)

	ch := make(chan struct{})
	go func() {
		defer close(ch)

		for {
			if err := ctx.Err(); err != nil {
				slog.Info("Stopping tunnel listener")
				return
			}

			conn, err := listener.Accept(ctx)
			if err != nil {
				slog.Error("Error accepting connection", "error", err)
				continue
			}

			slog.Debug("Accepted connection", "version", conn.ConnectionState().Version)

			if err := s.register(conn); err != nil {
				level := slog.LevelError
				if errors.Is(err, auth.ErrUnauthorized) {
					level = slog.LevelDebug
				}

				// close connection with error
				conn.CloseWithError(1, err.Error())

				slog.Log(ctx, level, "Registering connection", "error", err)

				continue
			}

			go func() {
				<-ctx.Done()
				conn.CloseWithError(protocol.ApplicationOK, "server closing down")
			}()

			slog.Debug("Server registered")
		}
	}()

	slog.Info("HTTP listener starting...", "addr", httpServer.Addr)

	if err := httpServer.ListenAndServe(); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}

	select {
	case <-ch:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("deadline exceeded waiting for tunnel server shutdown")
	}
}

// ServeHTTP proxies requests onto tunnel endpoints based on the presence
// of and targets defined in the requests X-Forwarded-Host or Host headers.
// These headers are used to identify the target tunnel group and then the request
// is forwarded onto the next available connection in a round-robbin sequence.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := slog.With("method", r.Method, "path", r.URL.Path)
	log.Debug("Handling request")

	var err error
	defer func() {
		log.Debug("Finished handling request", "error", err)
	}()

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}

	client, ok := s.clients[host]
	if !ok {
		log.Debug("Unexpected client host requested", "host", host)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	r = r.Clone(r.Context())
	r.URL.Scheme = "https"
	r.URL.Host = s.conf.TunnelAddress
	r.RequestURI = ""

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)

	for k, v := range resp.Trailer {
		w.Header()[k] = v
	}
}

// register adds a newly accepted connection onto the identified target tunnel group.
func (s *Server) register(conn quic.EarlyConnection) error {
	stream, err := conn.AcceptStream(conn.Context())
	if err != nil {
		return fmt.Errorf("accepting stream: %w", err)
	}

	defer stream.Close()

	dec := protocol.NewDecoder[protocol.RegisterListenerRequest](stream)
	defer dec.Close()

	req, err := dec.Decode()
	if err != nil {
		return fmt.Errorf("decoding register listener request: %w", err)
	}

	enc := protocol.NewEncoder[protocol.RegisterListenerResponse](stream)
	defer enc.Close()

	if err := s.handler.Authenticate(&req); err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			writeError(enc, err, protocol.CodeUnauthorized)
			return err
		}

		writeError(enc, err, protocol.CodeServerError)
		return err
	}

	tripper, ok := s.trippers[req.TunnelGroup]
	if !ok {
		err := fmt.Errorf("tunnel group unknown: %q", req.TunnelGroup)
		writeError(enc, err, protocol.CodeBadRequest)
		return err
	}

	resp := &protocol.RegisterListenerResponse{
		Version: protocol.Version,
		Code:    protocol.CodeOK,
	}

	if err := enc.Encode(resp); err != nil {
		return fmt.Errorf("encoding register listener response: %w", err)
	}

	tripper.register(conn)

	return nil
}

func writeError(enc protocol.Encoder[protocol.RegisterListenerResponse], err error, code protocol.ResponseCode) {
	_ = enc.Encode(&protocol.RegisterListenerResponse{
		Version: protocol.Version,
		Code:    code,
		Body:    []byte(err.Error()),
	})
}

type roundRobbinTripper struct {
	set roundrobbin.Set[http.RoundTripper]
}

func (r *roundRobbinTripper) register(first quic.EarlyConnection) {
	// connection can only be safely used once as the calling
	// client will establish a h3 session (control stream) after each dial
	// which can only be safely done once
	conns := make(chan quic.EarlyConnection, 1)
	conns <- first
	close(conns)

	r.set.Register(first.Context(), &http3.RoundTripper{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			slog.Debug("Dial", "addr", addr, "remote_addr", first.RemoteAddr())

			conn, ok := <-conns
			if ok {
				return conn, nil
			}

			first.CloseWithError(protocol.ApplicationError, "Connection closing")

			return nil, net.ErrClosed
		},
	})
}

func (r *roundRobbinTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}()

	for {
		rt, ok, err := r.set.Next(req.Context())
		if err != nil {
			// can only be context error
			continue
		}

		if !ok {
			return nil, net.ErrClosed
		}

		resp, err := rt.RoundTrip(req)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				r.set.Remove(rt)
				continue
			}
		}

		return resp, err
	}
}
