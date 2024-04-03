package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/quic-go/quic-go"
	"go.flipt.io/reverst/internal/config"
	"go.flipt.io/reverst/internal/protocol"
	"gopkg.in/yaml.v3"
)

type conf struct {
	Level            config.Level `ff:" short=l | long=log            | default=info             | usage: 'debug, info, warn or error'                           "`
	ServerName       string       `ff:" short=n | long=server-name    |                            usage: server name used to identify tunnel via TLS (required) "`
	TunnelAddress    string       `ff:" short=a | long=tunnel-address | default='127.0.0.1:7171' | usage: address for accepting tunnelling quic connections      "`
	HTTPAddress      string       `ff:" short=s | long=http-address   | default='127.0.0.1:8181' | usage: address for serving HTTP requests                      "`
	TunnelGroupsPath string       `ff:" short=g | long=tunnel-groups  | default='groups.yml'     | usage: path to tunnel groups configuration file               "`

	MaxIdleTimeout  time.Duration `ff:" long=max-idle-timeout  | default=1m  | usage: maximum time a connection can be idle "`
	KeepAlivePeriod time.Duration `ff:" long=keep-alive-period | default=30s | usage: period between keep-alive events      "`
}

func (c conf) validate() error {
	if c.ServerName == "" {
		return errors.New("server-name must be non-empty string")
	}

	return nil
}

func main() {
	flags := ff.NewFlagSet("reverst")

	var conf conf
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

			if err := conf.validate(); err != nil {
				return err
			}

			handler := protocol.AuthenticationHandlerFunc(func(_ *protocol.RegisterListenerRequest) error {
				return nil
			})

			return runServer(ctx, conf, handler)
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

func runServer(ctx context.Context, conf conf, handle protocol.AuthenticationHandler) error {
	slog.Info("QUIC listener starting...", "addr", conf.TunnelAddress)

	listener, err := quic.ListenAddrEarly(conf.TunnelAddress, generateTLSConfig(conf.ServerName), &quic.Config{
		MaxIdleTimeout:  conf.KeepAlivePeriod,
		KeepAlivePeriod: conf.MaxIdleTimeout,
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	var groups config.TunnelGroups
	fi, err := os.Open(conf.TunnelGroupsPath)
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	defer fi.Close()

	if err := yaml.NewDecoder(fi).Decode(&groups); err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	server := newServer(conf.TunnelAddress, handle, groups)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				slog.Error("Error accepting connection", "error", err)
				continue
			}

			slog.Debug("Accepted connection", "version", conn.ConnectionState().Version)

			if err := server.Register(conn); err != nil {
				slog.Error("Registering connection", "error", err)
				continue
			}

			slog.Debug("Server registered")
		}
	}()

	slog.Info("HTTP listener starting...", "addr", conf.HTTPAddress)

	return http.ListenAndServe(conf.HTTPAddress, server)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig(srvName string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{protocol.Name},
		ServerName:   srvName,
	}
}
