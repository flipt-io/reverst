package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"go.flipt.io/reverst/client"
	"go.flipt.io/reverst/internal/protocol"
	"golang.org/x/sync/errgroup"
)

var (
	srvName = flag.String("server-name", "flipt.dev.local", "Server name to advertise")
	addr    = flag.String("addr", "127.0.0.1:7171", "Address on which to connect and establish tunnel")
	user    = flag.String("username", "", "username for basic authentication")
	passw   = flag.String("password", "", "password for basic authentication")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	server := &client.Server{
		TunnelGroup: *srvName,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("PONG"))
		}),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{protocol.Name},
			ServerName:         *srvName,
		},
	}

	if *user != "" {
		server.Authenticator = client.BasicAuthenticator(*user, *passw)
	}

	var group errgroup.Group
	group.Go(func() error {
		defer func() {
			slog.Info("Server closed")
			cancel()
		}()

		return server.DialAndServe(ctx, *addr)
	})

	<-ctx.Done()

	slog.Info("Exiting...")
	defer slog.Info("Finished")

	stop()

	if err := server.Close(); err != nil {
		slog.Error("Failure on server close", "error", err)
	}

	if err := group.Wait(); err != nil {
		slog.Error("Error on shutdown", "error", err)
	}

}
