package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/peterbourgon/ff/v4/ffyaml"
	"github.com/quic-go/quic-go"
	"go.flipt.io/reverst/client"
	"go.flipt.io/reverst/pkg/protocol"
)

func main() {
	flags := ff.NewFlagSet("reverst")
	_ = flags.StringLong("config", "config.yml", "path to config file")

	var conf Config
	if err := flags.AddStruct(&conf); err != nil {
		panic(err)
	}

	httpcmd := &ff.Command{
		Name:  "http",
		Usage: "http [FLAGS] [ADDR]",
		Flags: flags,
		Exec: func(ctx context.Context, args []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: slog.Level(conf.Level),
			}))

			slog.SetDefault(logger)

			if err := conf.Validate(); err != nil {
				return err
			}

			addr := args[0]
			if !strings.Contains(addr, ":") {
				addr = fmt.Sprintf("http://0.0.0.0:%s", addr)
			}

			targetURL, err := url.Parse(addr)
			if err != nil {
				return err
			}

			tlsConf := &tls.Config{
				MinVersion:         tls.VersionTLS13,
				NextProtos:         []string{protocol.Name},
				ServerName:         conf.ServerName,
				InsecureSkipVerify: conf.InsecureSkipVerify,
			}

			tlsConf.RootCAs, _ = x509.SystemCertPool()
			if tlsConf.RootCAs == nil {
				tlsConf.RootCAs = x509.NewCertPool()
			}

			if conf.CACertificatePath != "" {
				caCertRaw, err := os.ReadFile(conf.CACertificatePath)
				if err != nil {
					return err
				}

				if !tlsConf.RootCAs.AppendCertsFromPEM(caCertRaw) {
					return fmt.Errorf("failed to append cert at path: %q", conf.CACertificatePath)
				}
			}

			tunnelGroup := conf.TunnelGroup
			if tunnelGroup == "" {
				tunnelGroup = conf.ServerName
			}

			logger = logger.With(
				"tunnel_group", tunnelGroup,
				"server_name", conf.ServerName,
				"target", targetURL,
			)

			var (
				auth   client.Authenticator
				scheme = conf.Scheme
			)
			if conf.Username != "" {
				if scheme == "" {
					scheme = "Basic"
				}

				auth = client.BasicAuthenticator(
					conf.Username,
					conf.Password,
					client.WithScheme(scheme),
				)
			} else if conf.Token != "" {
				if scheme == "" {
					scheme = "Bearer"
				}

				auth = client.BearerAuthenticator(conf.Token, client.WithScheme(scheme))
			}

			return (&client.Server{
				TunnelGroup:   tunnelGroup,
				Handler:       httputil.NewSingleHostReverseProxy(targetURL),
				Logger:        logger,
				Authenticator: auth,
				TLSConfig:     tlsConf,
				QuicConfig: &quic.Config{
					MaxIdleTimeout:  conf.MaxIdleTimeout,
					KeepAlivePeriod: conf.KeepAlivePeriod,
				},
			}).DialAndServe(ctx, conf.TunnelAddress)
		},
	}

	cmd := &ff.Command{
		Name:  "reverst",
		Usage: "reverst [FLAGS] [COMMAND]",
		Subcommands: []*ff.Command{
			httpcmd,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()

	if err := cmd.ParseAndRun(ctx, os.Args[1:],
		ff.WithEnvVarPrefix("REVERST"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ffyaml.Parse),
		ff.WithConfigAllowMissingFile(),
	); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}

		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Command(cmd))
		if !errors.Is(err, ff.ErrHelp) {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}

		os.Exit(1)
	}
}
