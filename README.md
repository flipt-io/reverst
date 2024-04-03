reverst: HTTP reverse tunnels over QUIC
---------------------------------------

> Ti esrever dna ti pilf nwod gnaht ym tup i

Reverst is a (load-balanced) reverse-tunnel server and Go server-client library built on QUIC and HTTP/3.

- Go Powered: Written in Go using [quic-go](github.com/quic-go/quic-go)
- Compatible: The Go `client` package is built on `net/http` standard-library abstractions
- Load-balanced: Run multiple instances of your services behind the same tunnel
- Performant: Built on-top of QUIC and HTTP/3

## Building

```
go install ./cmd/...
```

## Usage

### `reverst` tunnel server

```
➜  reverst -h
COMMAND
  reverst

USAGE
  reverst [FLAGS]

FLAGS
  -l, --log LEVEL                    debug, info, warn or error (default: INFO)
  -n, --server-name STRING           server name used to identify tunnel via TLS (required)
  -a, --tunnel-address STRING        address for accepting tunnelling quic connections (default: 127.0.0.1:7171)
  -s, --http-address STRING          address for serving HTTP requests (default: 127.0.0.1:8181)
  -g, --tunnel-groups STRING         path to tunnel groups configuration file (default: groups.yml)
      --max-idle-timeout DURATION    maximum time a connection can be idle (default: 1m0s)
      --keep-alive-period DURATION   period between keep-alive events (default: 30s)
```
