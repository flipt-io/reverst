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
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
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
	"go.opentelemetry.io/otel/metric"
)

// ErrNotFound is returned when a requested tunnel group cannot be located
var ErrNotFound = errors.New("not found")

type Server struct {
	metrics

	conf config.Config

	mu      sync.RWMutex
	handler protocol.AuthenticationHandler
	// trippersByGroup maps tunnel group names onto roundRobbinTripper instances
	trippersByGroup map[string]*roundRobbinTripper
	// handlersByHost maps host names onto target proxy handlers
	handlersByHost map[string]*httputil.ReverseProxy
}

// New constructs and configures a new reverst Server.
func New(conf config.Config, groupChan <-chan *config.TunnelGroups) (*Server, error) {
	groups, ok := <-groupChan
	if !ok {
		return nil, errors.New("tunnel groups channel closed")
	}

	s := &Server{
		conf:            conf,
		handler:         groups.AuthenticationHandler(),
		trippersByGroup: map[string]*roundRobbinTripper{},
		handlersByHost:  map[string]*httputil.ReverseProxy{},
	}

	var err error
	s.metrics, err = newMetrics(conf.ManagementAddress)
	if err != nil {
		return nil, err
	}

	target, err := url.Parse("https://" + conf.TunnelAddress)
	if err != nil {
		return nil, err
	}

	for name, group := range groups.Groups {
		slog.Debug("Registering tunnel group", "name", name, "hosts", group.Hosts)

		tripper, err := newRoundRobbinTipper(s.Meter, name)
		if err != nil {
			return nil, err
		}

		s.trippersByGroup[name] = tripper
		for _, host := range group.Hosts {
			s.handlersByHost[host] = proxyHandler(tripper, target)
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
					tripper, ok := s.trippersByGroup[name]
					if !ok {
						var err error
						tripper, err = newRoundRobbinTipper(s.Meter, name)
						if err != nil {
							slog.Error("Building client transport", "error", err)
							continue
						}

						s.trippersByGroup[name] = tripper
					}

					for _, host := range group.Hosts {
						s.handlersByHost[host] = proxyHandler(tripper, target)
					}
				}

				// remove trippers for now non-existent groups
				for name, tripper := range s.trippersByGroup {
					if _, ok := groups.Groups[name]; ok {
						continue
					}

					for name, h := range s.handlersByHost {
						if h.Transport == tripper {
							delete(s.handlersByHost, name)
						}
					}

					delete(s.trippersByGroup, name)
				}
			}()

			log.Info("Tunnel groups updated")
		}
	}()

	return s, nil
}

func proxyHandler(tripper http.RoundTripper, target *url.URL) *httputil.ReverseProxy {
	handler := httputil.NewSingleHostReverseProxy(target)
	handler.Transport = tripper
	return handler
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
				code := protocol.ApplicationError
				level := slog.LevelError
				if errors.Is(err, auth.ErrUnauthorized) {
					code = protocol.ApplicationClientError
					level = slog.LevelDebug
				}

				slog.Log(ctx, level, "Closing connection", "error", err)
				conn.CloseWithError(code, cause(err).Error())

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
	handler, ok := s.handlersByHost[host]
	s.mu.RUnlock()
	if !ok {
		log.Debug("Unexpected client host requested", "host", host)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	handler.ServeHTTP(w, r)

	return
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

	w := &responseWriter{
		enc: protocol.NewEncoder[protocol.RegisterListenerResponse](stream),
	}

	defer func() {
		w.enc.Close()

		attrs := []attribute.KeyValue{tunnelGroupKey.String(req.TunnelGroup)}
		if err != nil {
			attrs = append(attrs, errorKey.String(cause(err).Error()))
		}

		s.tunnelGroupRegistrationsTotal.Add(
			context.Background(),
			1,
			metric.WithAttributes(attrs...),
		)
	}()

	tripper, ok := s.trippersByGroup[req.TunnelGroup]
	if !ok {
		return fmt.Errorf("tunnel group: %q: %w", req.TunnelGroup, ErrNotFound)
	}

	if err := s.handler.Authenticate(&req); err != nil {
		return err
	}

	if err := w.write(nil); err != nil {
		return fmt.Errorf("encoding register listener response: %w", err)
	}

	tripper.register(conn)

	return nil
}

type responseWriter struct {
	enc protocol.Encoder[protocol.RegisterListenerResponse]
}

func (w *responseWriter) write(body []byte) error {
	return w.enc.Encode(&protocol.RegisterListenerResponse{
		Version: protocol.Version,
		// deprecated: this is going away and we will always
		// just close the connection in the future and explain
		// why via the application error code on close
		Code: protocol.CodeOK,
		Body: body,
	})
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

	tr.set = roundrobbin.NewSet(
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
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
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
		log := log.With("path", r.URL.Path)
		log.Debug("Request started")

		wr := &statusInterceptResponseWriter{ResponseWriter: w}
		defer func() {
			log.Debug("Request finished", "code", wr.code, "ellapsed", time.Since(start))
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

func cause(err error) (cerr error) {
	cerr = err
	if err = errors.Unwrap(err); err != nil {
		return cause(err)
	}

	return
}
