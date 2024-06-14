package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
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

	var (
		tunnelAddr    = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)
		tunnelHTTPURL = fmt.Sprintf("http://%s:%d", *integrationHost, *integrationHTTPPort)
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var group errgroup.Group
	startServer(t, ctx, &group, tunnelAddr, stringHandler(`{"hello":"world"}`))

	resp, err := http.Get(tunnelHTTPURL)
	require.NoError(t, err)

	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, `{"hello":"world"}`, string(bytes))

	cancel()

	_ = group.Wait()
}

func TestBadRequest(t *testing.T) {
	if !*integrationTest {
		t.Skip("integration testing disabled")
		return
	}

	var (
		tunnelAddr    = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)
		tunnelHTTPURL = fmt.Sprintf("http://%s:%d", *integrationHost, *integrationHTTPPort)
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var group errgroup.Group
	startServer(t, ctx, &group, tunnelAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))

	resp, err := http.Get(tunnelHTTPURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	bytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "bad request\n", string(bytes))

	cancel()

	_ = group.Wait()
}

func TestUnauthorized(t *testing.T) {
	if !*integrationTest {
		t.Skip("integration testing disabled")
		return
	}

	var tunnelAddr = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	server := &client.Server{
		TunnelGroup: "local.example",
		Handler:     &http.ServeMux{},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{protocol.Name},
			ServerName:         "local.example",
		},
		Authenticator: client.BasicAuthenticator("user", "wrongpassword"),
	}

	require.ErrorIs(t, server.DialAndServe(ctx, tunnelAddr), client.ErrUnauthorized)
}

func TestMultipleTunnels(t *testing.T) {
	if !*integrationTest {
		t.Skip("integration testing disabled")
		return
	}

	var (
		tunnelAddr    = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)
		tunnelHTTPURL = fmt.Sprintf("http://%s:%d", *integrationHost, *integrationHTTPPort)
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var group errgroup.Group
	startServer(t, ctx, &group, tunnelAddr, stringHandler("a"))
	startServer(t, ctx, &group, tunnelAddr, stringHandler("b"))

	var responses []string
	for i := 0; i < 10; i++ {
		resp, err := http.Get(tunnelHTTPURL)
		require.NoError(t, err)

		defer resp.Body.Close()

		bytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		responses = append(responses, string(bytes))
	}

	assert.Equal(t, []string{"a", "b", "a", "b", "a", "b", "a", "b", "a", "b"}, responses)

	cancel()

	_ = group.Wait()
}

func TestConcurrentSlowRequests(t *testing.T) {
	if !*integrationTest {
		t.Skip("integration testing disabled")
		return
	}

	var (
		tunnelAddr    = fmt.Sprintf("%s:%d", *integrationHost, *integrationTunnelPort)
		tunnelHTTPURL = fmt.Sprintf("http://%s:%d", *integrationHost, *integrationHTTPPort)
	)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var serverGroup errgroup.Group
	startServer(t, ctx, &serverGroup, tunnelAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(100*rand.Intn(10)) * time.Millisecond)
		w.Write([]byte("foo"))
	}))

	var clientGroup errgroup.Group
	for i := 0; i < 1000; i++ {
		clientGroup.Go(func() error {
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", tunnelHTTPURL, nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				return nil
			}

			require.NoError(t, err)
			defer resp.Body.Close()

			bytes, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, []byte("foo"), bytes)
			return nil
		})
	}

	require.NoError(t, clientGroup.Wait())

	cancel()

	_ = serverGroup.Wait()
}

type stringHandler string

func (s stringHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(s))
}

func startServer(t *testing.T, ctx context.Context, group *errgroup.Group, tunnelAddr string, handler http.Handler) {
	t.Helper()

	mux := &http.ServeMux{}
	mux.Handle("/", handler)

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

	group.Go(func() error {
		defer func() {
			t.Log("Server closed")
		}()

		return server.DialAndServe(ctx, tunnelAddr)
	})

	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for tunnel connection")
	}
}
