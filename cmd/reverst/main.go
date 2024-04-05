package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/quic-go/quic-go"
	"go.flipt.io/reverst/internal/auth"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/pkg/protocol"
	"gopkg.in/yaml.v3"
)

func main() {
	flags := ff.NewFlagSet("reverst")

	var conf config.Config
	if err := flags.AddStruct(&conf); err != nil {
		panic(err)
	}

	cmd := &ff.Command{
		Name:  "reverst",
		Usage: "reverst [FLAGS]",
		Flags: flags,
		Exec: func(ctx context.Context, args []string) error {
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.Level(conf.Level),
			})))

			if err := conf.Validate(); err != nil {
				return err
			}

			return runServer(ctx, conf)
		},
	}

	if err := cmd.ParseAndRun(context.Background(), os.Args[1:],
		ff.WithEnvVarPrefix("REVERST"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Command(cmd))
		if !errors.Is(err, ff.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}

		os.Exit(1)
	}
}

func runServer(ctx context.Context, conf config.Config) error {
	slog.Info("QUIC listener starting...", "addr", conf.TunnelAddress)

	tlsCert, err := tls.LoadX509KeyPair(conf.CertificatePath, conf.PrivateKeyPath)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{protocol.Name},
		ServerName:   conf.ServerName,
	}

	listener, err := quic.ListenAddrEarly(conf.TunnelAddress, tlsConfig, &quic.Config{
		MaxIdleTimeout:  conf.KeepAlivePeriod,
		KeepAlivePeriod: conf.MaxIdleTimeout,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	fi, err := os.Open(conf.TunnelGroupsPath)
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	defer fi.Close()

	var groups config.TunnelGroups
	if err := yaml.NewDecoder(fi).Decode(&groups); err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	handler, err := groups.AuthenticationHandler()
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	server := newServer(conf.TunnelAddress, handler, groups)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				slog.Error("Error accepting connection", "error", err)
				continue
			}

			slog.Debug("Accepted connection", "version", conn.ConnectionState().Version)

			if err := server.Register(conn); err != nil {
				level := slog.LevelError
				if errors.Is(err, auth.ErrUnauthorized) {
					level = slog.LevelDebug
				}

				// close connection with error
				conn.CloseWithError(1, err.Error())

				slog.Log(ctx, level, "Registering connection", "error", err)

				continue
			}

			slog.Debug("Server registered")
		}
	}()

	slog.Info("HTTP listener starting...", "addr", conf.HTTPAddress)

	return http.ListenAndServe(conf.HTTPAddress, server)
}
