reverst: HTTP reverse tunnels over QUIC
---------------------------------------

> Ti esrever dna ti pilf nwod gnaht ym tup i

<p align="center">
  <img width="300" height="300" src="./docs/gopher-glasses.svg" alt="Tunnel Gopher">
</p>

Reverst is a (load-balanced) reverse-tunnel server and Go server-client library built on QUIC and HTTP/3.

- Go Powered: Written in Go using [quic-go](https://github.com/quic-go/quic-go)
- Compatible: The Go `client` package is built on `net/http` standard-library abstractions
- Load-balanced: Run multiple instances of your services behind the same tunnel
- Performant: Built on top of QUIC and HTTP/3

## Use-case

Reverst is for exposing services on the public internet from within restrictive networks (e.g. behind NAT gateways).
The tunnel binary is intended to be deployed on the public internet.
Client servers then dial out to the tunnels and register themselves on target tunnel groups.
A tunnel group is a load-balanced set of client-servers, which is exposed through the reverst tunnel HTTP interface.

## Client

[![Go Reference](https://pkg.go.dev/badge/go.flipt.io/reverst/client.svg)](https://pkg.go.dev/go.flipt.io/reverst/client)

The following section refers to the Go tunnel client code.
This can be added as a dependency to any Go code that requires exposing through a `reverstd` tunnel server.

### Install
  
```console
go get go.flipt.io/reverst/client
```

### Building

```console
go install ./client/...
```

## Server and CLI

### Building

The following builds both `reverstd` (tunnel server) and `reverst` (tunnel cli client).

```console
go install ./cmd/...
```

### Testing

Reverst uses Dagger to setup and run an integration test suite.

#### Unit

```console
dagger call testUnit --source=.
```

#### Integration

```console
dagger call testIntegration --source=.
```

The test suite sets up a tunnel, registers a server-client to the tunnel and then requests the service through the tunnels HTTP interface.

### Examples

Head over to the [examples](./examples) directory for some walkthroughs running `reverstd` and `reverst`.

### Usage and Configuration

#### Command-Line Flags and Environment Variables

The following flags can be used to configure a running instance of the `reverst` server.

```console
➜  reverstd -h
COMMAND
  reverstd

USAGE
  reverstd [FLAGS]

FLAGS
  -l, --log LEVEL                    debug, info, warn or error (default: INFO)
  -a, --tunnel-address STRING        address for accepting tunnelling quic connections (default: 127.0.0.1:7171)
  -s, --http-address STRING          address for serving HTTP requests (default: 0.0.0.0:8181)
  -n, --server-name STRING           server name used to identify tunnel via TLS (required)
  -k, --private-key-path STRING      path to TLS private key PEM file (required)
  -c, --certificate-path STRING      path to TLS certificate PEM file (required)
  -g, --tunnel-groups STRING         path to file or k8s configmap identifier (default: groups.yml)
  -w, --watch-groups                 watch tunnel groups sources for updates
      --management-address STRING    HTTP address for management API
      --max-idle-timeout DURATION    maximum time a connection can be idle (default: 1m0s)
      --keep-alive-period DURATION   period between keep-alive events (default: 30s)
```

The long form names of each flag can also be referenced as environment variable names.
To do so, prefix them with `REVERST_`, replace each `-` with `_` and uppercase the letters.

For example, `--tunnel-address` becomes `REVERST_TUNNEL_ADDRESS`.

#### Tunnel Groups Configuration YAML

**configuring**

Currently, the tunnel groups configuration can be sourced from two different locations types (`file` and `k8s`).
Both tunnel group sources support watching sources for changes over time (see `-w` flag).

- Local filesystem (`file://[path]`)

The standard and simplest method is to point `reverstd` at your configuration YAML file on your machine via its path.

```console
reverstd -g path/to/configuration.yml
// alternatively:
reverstd -g file:///path/to/configuration.yml
```

- Kubernetes ConfigMap `k8s://configmap/[namespace]/[name]/[key]`

Alternatively, you can configure reverst to connect to a Kubernetes API server and fetch / watch configuration from.

```console
reverstd -g k8s://configmap/default/tunnelconfig/groups.yml
```

**defining**

The `reverstd` server take a path to a YAML encoded file, which identifies the tunnel groups to be hosted.
A tunnel group is a load-balancer on which tunneled servers can register themselves.
The file contains a top-level key groups, under which each tunnel group is uniquely named.

```yaml
groups:
  "group-name":
    hosts:
    - "some.host.address.dev" # Host for routing inbound HTTP requests to tunnel group
    authentication:
      basic:
        username: "user"
        password: "pass"
```

Each group body contains import details for configuring the tunnel groups.

**hosts**

This is an array of strings which is used in routing HTTP requests to the tunnel group when one of the hostnames matches.

**authentication**

This identifies how to authenticate new tunnels attempting to register with the group.
Multiple authentication strategies can be enabled at once.
The following types are supported:

- `basic` supports username and password authentication (default scheme `Basic`)
- `bearer` supports static token based matching (default scheme `Bearer`)
- `external` supports offloading authentication and authorization to an external service (default scheme `Bearer`)

> [!Note]
> If enabling both `bearer` and `external` you will need to override one of their schemes to distinguish them.

<details>

<summary>Example configuration with multiple authentication strategies</summary>

The following contains all three strategies (basic, bearer and external) enabled at once with different schemes:

```yaml
groups:
  "group-name":
    hosts:
    - "some.host.address.dev" # Host for routing inbound HTTP requests to tunnel group
    authentication:
      basic:
        username: "user"
        password: "pass"
      bearer:
        token: "some-token"
      external:
        scheme: "JWT"
        endpoint: "http://some-external-endpoint/auth/ext"
```

</details>

If no strategies are supplied then authentication is disabled (strongly discouraged).
