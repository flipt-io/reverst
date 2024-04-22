package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/roundrobbin"
	"go.flipt.io/reverst/pkg/protocol"
)

type Server struct {
	address string
	handler protocol.AuthenticationHandler

	// trippers maps tunnel group identifiers onto roundRobbinTripper instances
	trippers map[string]*roundRobbinTripper
	// clients maps host names onto target clients
	clients map[string]*http.Client
}

func newServer(address string, handler protocol.AuthenticationHandler, groups config.TunnelGroups) *Server {
	s := &Server{
		address:  address,
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

	return s
}

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
	r.URL.Host = s.address
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

func (s *Server) Register(conn quic.EarlyConnection) error {
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

		if errors.Is(err, context.Canceled) {
			slog.Debug("RoundTrip", "error", err)

			return &http.Response{
				Request:    req,
				StatusCode: http.StatusInternalServerError,
				Body:       nil,
			}, nil
		}

		return resp, err
	}
}
