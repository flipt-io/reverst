package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/protocol"
	"go.flipt.io/reverst/internal/roundrobbin"
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

	host := r.Host
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
		writeError(enc, err, protocol.CodeBadRequest)
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

func (r *roundRobbinTripper) register(conn quic.EarlyConnection) {
	r.set.Register(conn.Context(), &http3.RoundTripper{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			return conn, nil
		},
	})
}

func (r *roundRobbinTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}()

	rt, ok := r.set.Next(req.Context())
	if !ok {
		return nil, net.ErrClosed
	}

	return rt.RoundTrip(req)
}
