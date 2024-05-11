package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/roundrobbin"
	"go.flipt.io/reverst/pkg/protocol"
	"go.opentelemetry.io/otel/attribute"
	prom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

type Server struct {
	conf config.Config

	mu      sync.RWMutex
	handler protocol.AuthenticationHandler
	// trippers maps tunnel group identifiers onto roundRobbinTripper instances
	trippers map[string]*roundRobbinTripper
	// clients maps host names onto target clients
	clients map[string]*http.Client

	tunnelGroupRegistrationsTotal metric.Int64Counter
	proxyRequestsHandledTotal     metric.Int64Counter
	proxyRequestsLatency          metric.Float64Histogram
}

// New constructs and configures a new reverst Server.
func New(conf config.Config, groupChan <-chan *config.TunnelGroups) (*Server, error) {
	groups, ok := <-groupChan
	if !ok {
		return nil, errors.New("tunnel groups channel closed")
	}

	s := &Server{
		conf:     conf,
		handler:  groups.AuthenticationHandler(),
		trippers: map[string]*roundRobbinTripper{},
		clients:  map[string]*http.Client{},
	}
	meter := noop.NewMeterProvider().Meter(meterName)
	if conf.ManagementAddress != "" {
		exporter, err := prom.New()
		if err != nil {
			log.Fatal(err)
		}

		provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
		meter = provider.Meter(meterName)
	}

	var err error
	s.tunnelGroupRegistrationsTotal, err = meter.Int64Counter(
		prometheus.BuildFQName(namespace, tunnelGroupSubsystem, "registrations_total"),
		metric.WithDescription("Total number of registration attempts handled by tunnel group and status code"),
	)
	if err != nil {
		return nil, err
	}

	s.proxyRequestsHandledTotal, err = meter.Int64Counter(
		prometheus.BuildFQName(namespace, proxySubsystem, "requests_total"),
		metric.WithDescription("Total number of requests handled by host and response code"),
	)
	if err != nil {
		return nil, err
	}

	s.proxyRequestsLatency, err = meter.Float64Histogram(
		prometheus.BuildFQName(namespace, proxySubsystem, "requests_latency"),
		metric.WithDescription("Latency of requests per host and response code"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, err
	}

	for name, group := range groups.Groups {
		slog.Debug("Registering tunnel group", "name", name, "hosts", group.Hosts)

		tripper, err := newRoundRobbinTipper(meter, name)
		if err != nil {
			return nil, err
		}

		s.trippers[name] = tripper

		client := &http.Client{
			Transport: tripper,
		}

		for _, host := range group.Hosts {
			s.clients[host] = client
		}
	}

	go func() {
		log := slog.With("tunnel_groups_path", conf.TunnelGroups)
		defer log.Info("Closing tunnel groups watcher")

		for groups := range groupChan {
			log.Debug("Tunnel groups configuration update received")

			func() {
				s.mu.Lock()
				defer s.mu.Unlock()

				// update authentication handle to account for new groups
				s.handler = groups.AuthenticationHandler()

				// add any new trippers and associated clients
				for name, group := range groups.Groups {
					tripper, ok := s.trippers[name]
					if !ok {
						var err error
						tripper, err = newRoundRobbinTipper(meter, name)
						if err != nil {
							slog.Error("Building client transport", "error", err)
							continue
						}

						s.trippers[name] = tripper
					}

					client := &http.Client{
						Transport: tripper,
					}

					for _, host := range group.Hosts {
						s.clients[host] = client
					}
				}

				// remove trippers and clients for now non-existent groups
				for name, tripper := range s.trippers {
					if _, ok := groups.Groups[name]; ok {
						continue
					}

					for name, client := range s.clients {
						if client.Transport == tripper {
							delete(s.clients, name)
						}
					}

					delete(s.trippers, name)
				}
			}()

			log.Info("Tunnel groups updated")
		}
	}()

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
		MaxIdleTimeout:  s.conf.MaxIdleTimeout,
		KeepAlivePeriod: s.conf.KeepAlivePeriod,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

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

	if s.conf.ManagementAddress != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", logHandler(slog.With("component", "management"), promhttp.Handler()))
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

		go http.ListenAndServe(s.conf.ManagementAddress, mux)
	}

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
	start := time.Now().UTC()

	log := slog.With("method", r.Method, "path", r.URL.Path)
	log.Debug("Handling request")

	host, _, perr := net.SplitHostPort(r.Host)
	if perr != nil {
		host = r.Host
	}

	if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
		host = forwarded
	}

	wr := interceptStatus(w)
	w = wr

	var err error
	defer func() {
		attrs := attribute.NewSet(
			hostKey.String(host),
			statusKey.String(statusCodeToLabel(wr.StatusCode())),
		)
		s.proxyRequestsHandledTotal.Add(r.Context(), 1, metric.WithAttributeSet(attrs))
		s.proxyRequestsLatency.Record(r.Context(), float64(time.Since(start))/1e6, metric.WithAttributeSet(attrs))
		log.Debug("Finished handling request", "error", err)
	}()

	s.mu.RLock()
	client, ok := s.clients[host]
	s.mu.RUnlock()
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
		log.Error("Performing round trip", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
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
func (s *Server) register(conn quic.EarlyConnection) (err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

	w := &responseWriter{enc: protocol.NewEncoder[protocol.RegisterListenerResponse](stream)}
	defer func() {
		w.enc.Close()

		code := protocol.CodeServerError
		if w != nil {
			code = w.code
		}
		s.tunnelGroupRegistrationsTotal.Add(
			context.Background(),
			1,
			metric.WithAttributes(
				tunnelGroupKey.String(req.TunnelGroup),
				statusKey.String(code.String()),
			),
		)
	}()

	tripper, ok := s.trippers[req.TunnelGroup]
	if !ok {
		err := fmt.Errorf("tunnel group not found: %q", req.TunnelGroup)
		_ = w.write(err, protocol.CodeNotFound)
		return err
	}

	if err := s.handler.Authenticate(&req); err != nil {
		code := protocol.CodeServerError
		if errors.Is(err, auth.ErrUnauthorized) {
			code = protocol.CodeUnauthorized
			return err
		}

		_ = w.write(err, code)
		return err
	}

	if err := w.write(nil, protocol.CodeOK); err != nil {
		return fmt.Errorf("encoding register listener response: %w", err)
	}

	tripper.register(conn)

	return nil
}

type responseWriter struct {
	enc  protocol.Encoder[protocol.RegisterListenerResponse]
	code protocol.ResponseCode
}

func (w *responseWriter) write(err error, code protocol.ResponseCode) error {
	w.code = code

	resp := &protocol.RegisterListenerResponse{
		Version: protocol.Version,
		Code:    code,
	}

	if err != nil {
		resp.Body = []byte(err.Error())
	}

	return w.enc.Encode(resp)
}

type roundRobbinTripper struct {
	set *roundrobbin.Set[http.RoundTripper]

	activeConnectionsCount metric.Int64UpDownCounter

	attrs attribute.Set
}

func newRoundRobbinTipper(meter metric.Meter, tunnelGroup string) (_ *roundRobbinTripper, err error) {
	tr := roundRobbinTripper{
		attrs: attribute.NewSet(tunnelGroupKey.String(tunnelGroup)),
	}

	tr.activeConnectionsCount, err = meter.Int64UpDownCounter(
		prometheus.BuildFQName(namespace, tunnelGroupSubsystem, "active_conn"),
		metric.WithDescription("Number of active connections in the tunnel group"),
	)
	if err != nil {
		return nil, err
	}

	tr.set = roundrobbin.NewSet[http.RoundTripper](
		roundrobbin.WithOnEvict(func(http.RoundTripper) {
			tr.activeConnectionsCount.Add(
				context.Background(),
				-1,
				metric.WithAttributeSet(tr.attrs),
			)
		}),
	)

	return &tr, nil
}

func (r *roundRobbinTripper) register(first quic.EarlyConnection) {
	defer r.activeConnectionsCount.Add(context.Background(), 1, metric.WithAttributeSet(r.attrs))
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

// statusCodeToLabel normalize HTTP status codes into string labels
// 100s to 1XX
// 200s to 2XX
// and so on
func statusCodeToLabel(code int) string {
	if code == 0 {
		return "2XX"
	}

	if c := strconv.Itoa(code); len(c) > 0 {
		return c[:1] + "XX"
	}

	return "0XX"
}

type statusCodeResponseWriter interface {
	http.ResponseWriter
	StatusCode() int
}

func interceptStatus(w http.ResponseWriter) statusCodeResponseWriter {
	i := &statusInterceptResponseWriter{ResponseWriter: w}
	if _, ok := w.(io.ReaderFrom); !ok {
		return i
	}

	return readerFromDecorator{i}
}

type readerFromDecorator struct {
	*statusInterceptResponseWriter
}

func (d readerFromDecorator) ReadFrom(r io.Reader) (n int64, err error) {
	return d.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
}

func logHandler(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		log = log.With("path", r.URL.Path, "started_at", start)
		log.Debug("Request started")

		wr := &statusInterceptResponseWriter{ResponseWriter: w}
		defer func() {
			finished := time.Now().UTC()
			log.Debug("Request finished", "code", wr.code, "finished_at", finished, "ellapsed", time.Since(finished))
		}()

		h.ServeHTTP(wr, r)
	})
}

type statusInterceptResponseWriter struct {
	http.ResponseWriter

	code int
}

func (s *statusInterceptResponseWriter) WriteHeader(code int) {
	s.code = code
}

func (s *statusInterceptResponseWriter) StatusCode() int {
	return s.code
}
