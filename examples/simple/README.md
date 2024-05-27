Example Reverst Demonstration
-----------------------------

The following walks through experimenting with the simple server example.
This directory contains a number of things needed to stand up reverst and a registering client server:

- The example service in [./examples/simple/main.go](./examples/simple/main.go).
- Simple self-signed TLS private key and certificate.
- A `reverstd` tunnel-groups YAML file which serves the `localhost` group.
- A `reverst` CLI YAML file configured to connect to our tunnel.

## Building

Before we start you will need to build both `reverst` and `reverstd` to get this working.

```console
# from the root of this project run:

go install ./cmd/...
```

## Running

### Running `reverstd` tunnel server

The following command runs the tunnel server with:

- The QUIC tunnel listener on `127.0.0.1:7171`
- The HTTP serving listener on `127.0.0.1:8181`
- Logging with `debug` level
- A TLS server-name of `localhost`
- Some tunnel group definitions with a single tunnel group
  - The group has the name `localhost`
  - The group is reachable under the same host name
  - The group requires basic username and password authentication
- The dummy TLS certificates

```console
# from this simple example directory, run the following:

reverstd -l debug \
    -n localhost \
    -g group.yml \
    -k server.key \
    -c server.crt
```

### Running `reverst` tunnel client

Now you can run the `reverst` CLI to proxy to any processes listening locally on port `8080`.
It is setup to use the server client to register as a listener on the tunnel.

```console
reverst HTTP 8080
```

### Run something on `localhost:8080`

Now you're going to want to run something you want to be tunnelled on port `8080`.

For example, try running a python simple web server:

```console
python3 -m http.server 8080
```

This will serve the current directory tree as a HTML page over HTTP.

#### Making requests

You can now curl the _tunnel_ and requests will be forward all the way through to the python server.

```curl
curl localhost:8181
```
