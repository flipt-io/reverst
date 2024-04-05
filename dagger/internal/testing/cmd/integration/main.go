package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"go.flipt.io/reverst/client"
	"go.flipt.io/reverst/pkg/protocol"
	"golang.org/x/sync/errgroup"
)

var addr = flag.String("addr", "local.example:7171", "Address on which to connect and establish tunnel")

func main() {
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	mux := &http.ServeMux{}
	mux.Handle("/hello", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"hello":"world"}`))
	}))

	ch := make(chan struct{})

	server := &client.Server{
		TunnelGroup: "local.example",
		Handler:     mux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{protocol.Name},
			ServerName:         "local.example",
		},
		Authenticator: client.BasicAuthenticator("user", "pass"),
		OnConnectionReady: func(rlr protocol.RegisterListenerResponse) {
			close(ch)
		},
	}

	ctx, cancel := context.WithCancel(context.Background())

	var group errgroup.Group
	group.Go(func() error {
		defer func() {
			slog.Info("Server closed")
			cancel()
		}()

		return server.DialAndServe(ctx, *addr)
	})

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		slog.Error("timed out waiting for tunnel connection")
		os.Exit(1)
	}

	resp, err := http.Get("http://local.example:8181/hello")
	if err != nil {
		slog.Error("failed to get /hello", "error", err)
		os.Exit(1)
	}

	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("failed to read response body", "error", err)
		os.Exit(1)
	}

	if string(bytes) != `{"hello":"world"}` {
		slog.Error("unexpected response body", "found", string(bytes))
		os.Exit(1)
	}
}
