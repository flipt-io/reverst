// A generated module for Reverst functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"dagger/reverst/internal/dagger"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	goBuildCachePath = "/root/.cache/go-build"
	goModCachePath   = "/go/pkg/mod"
)

type Reverst struct{}

// Returns a built container with reverst on the path
func (m *Reverst) BuildContainer(
	ctx context.Context,
	source *dagger.Directory,
) (*Container, error) {
	build := dag.
		Go().
		FromVersion("1.22-alpine3.18").
		Build(source, dagger.GoBuildOpts{
			Packages: []string{"./cmd/reverst/..."},
		})

	return dag.
		Container().
		From("alpine:3.18").
		WithFile("/usr/local/bin/reverst", build.File("reverst")).
		WithEntrypoint([]string{"reverst"}), nil
}

func (m *Reverst) TestUnit(
	ctx context.Context,
	source *dagger.Directory,
) (string, error) {
	out, err := dag.Container().
		From("golang:1.22-alpine3.18").
		WithExec([]string{"apk", "add", "gcc", "build-base"}).
		With(dag.Go().GlobalCache).
		WithEnvVariable("CGO_ENABLED", "1").
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec([]string{"go", "test", "-race", "-count=5", "./..."}).
		Stdout(ctx)
	if err != nil {
		return out, err
	}

	return out, nil
}

func (m *Reverst) TestIntegration(
	ctx context.Context,
	source *dagger.Directory,
	//+optional
	verbose bool,
) (string, error) {
	ctr, err := m.BuildContainer(ctx, source)
	if err != nil {
		return "", err
	}

	key, cert, err := generateKeyPair()
	if err != nil {
		return "", err
	}

	reverst := ctr.
		WithEnvVariable("REVERST_LOG", "debug").
		WithEnvVariable("REVERST_TUNNEL_ADDRESS", "0.0.0.0:7171").
		WithEnvVariable("REVERST_SERVER_NAME", "local.example").
		WithNewFile("/etc/reverst/key.pem", dagger.ContainerWithNewFileOpts{
			Contents: string(key),
		}).
		WithEnvVariable("REVERST_PRIVATE_KEY_PATH", "/etc/reverst/key.pem").
		WithNewFile("/etc/reverst/cert.pem", dagger.ContainerWithNewFileOpts{
			Contents: string(cert),
		}).
		WithEnvVariable("REVERST_CERTIFICATE_PATH", "/etc/reverst/cert.pem").
		WithNewFile("/etc/reverst/groups.yml", dagger.ContainerWithNewFileOpts{
			Contents: `groups:
  "local.example":
    hosts: ["local.example"]
    authentication:
      basic:
        username: "user"
        password: "pass"
`,
		}).
		WithEnvVariable("REVERST_TUNNEL_GROUPS", "/etc/reverst/groups.yml").
		WithEnvVariable("REVERST_WATCH_GROUPS", "true").
		WithExposedPort(7171, dagger.ContainerWithExposedPortOpts{
			Protocol: dagger.Udp,
		}).
		WithExposedPort(8181, dagger.ContainerWithExposedPortOpts{
			Protocol: dagger.Tcp,
		}).
		WithExec(nil).
		AsService()

	cmd := []string{"go", "test", "./internal/test/...", "-integration"}
	if verbose {
		cmd = append(cmd, "-v")
	}

	out, err := dag.Container().
		From("golang:1.22-alpine3.18").
		WithServiceBinding("local.example", reverst).
		With(dag.Go().GlobalCache).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec(cmd).
		Stdout(ctx)
	if err != nil {
		return out, err
	}

	return out, nil
}

func (m *Reverst) Publish(
	ctx context.Context,
	source *dagger.Directory,
	password *Secret,
	//+optional
	//+default="ghcr.io"
	registry string,
	//+optional
	//+default="flipt-io"
	username string,
	//+optional
	//+default="reverst"
	image string,
	//+optional
	//+default="latest"
	tag string,
) (string, error) {
	ctr, err := m.BuildContainer(ctx, source)
	if err != nil {
		return "", err
	}

	return ctr.
		WithRegistryAuth(registry, username, password).
		Publish(ctx, fmt.Sprintf("%s/%s/%s:%s", registry, username, image, tag))
}

func generateKeyPair() ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	crt := x509.Certificate{
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Flipt",
			Organization: []string{"Flipt Corp."},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &crt, &crt, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	// Generate a pem block with the certificate
	return keyPem, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}), nil
}
