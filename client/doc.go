// package client
//
// The client package contains the client-side types for interfacing with reverst tunnels.
// The client itself is a http Server implementation that dials out to a tunnel server, performs
// a handshake to identify and authenticate the relevant tunnel group to register with, and then
// it switches roles into that of the server.
//
// # Example
//
//	package main
//
//	import (
//	    "context"
//	    "crypto/tls"
//	    "net/http"
//
//	    "go.flipt.io/reverst/client"
//	)
//
//	func main() {
//	    server := &client.Server {
//	        TunnelGroup: "some-group",
//	        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request {
//	            w.Write([]byte("Hello, World!"))
//	        })),
//	        TLSConfig: &tls.Config{InsecureSkipVerify: true}
//	    }
//
//	    server.DialAndServe(ctx, "some.reverst.tunnel:8443")
//	}
package client
