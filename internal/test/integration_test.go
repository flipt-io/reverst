package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.flipt.io/reverst/client"
	"go.flipt.io/reverst/pkg/protocol"
	"golang.org/x/sync/errgroup"
)

var (
	integrationTest       = flag.Bool("integration", false, "enable integration testing")
	integrationHost       = flag.String("integration-host", "local.example", "Hostname for local integration test revert tunnel")
	integrationTunnelPort = flag.Int("integration-tunnel-port", 7171, "Port for connecting to tunnel QUIC server")
	integrationHTTPPort   = flag.Int("integration-http-port", 8181, "Port for connecting to tunnel HTTP server")
)

func TestHelloWorld(t *testing.T) {
	if !*integrationTest {
		t.Skip("integration testing disabled")
		return
	}

	mux := &http.ServeMux{}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	var (
		tunnelAddr    = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)
		tunnelHTTPURL = fmt.Sprintf("http://%s:%d", *integrationHost, *integrationHTTPPort)
	)

	ctx, cancel := context.WithCancel(context.Background())

	var group errgroup.Group
	group.Go(func() error {
		defer func() {
			t.Log("Server closed")
			cancel()
		}()

		return server.DialAndServe(ctx, tunnelAddr)
	})

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tunnel connection")
	}

	resp, err := http.Get(tunnelHTTPURL)
	require.NoError(t, err)

	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"hello":"world"}`, string(bytes))

	require.NoError(t, server.Close())

	_ = group.Wait()
}
