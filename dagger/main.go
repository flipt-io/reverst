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
	"dagger/reverst/internal/dagger"
	"fmt"
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
		FromVersion("1.21-alpine3.18").
		Build(source, dagger.GoBuildOpts{
			Packages: []string{"./cmd/reverst/..."},
		})

	return dag.
		Container().
		From("alpine:3.18").
		WithFile("/usr/local/bin/reverst", build.File("reverst")).
		WithDefaultArgs([]string{"reverst"}), nil
}

func (m *Reverst) Publish(
	ctx context.Context,
	source *dagger.Directory,
	password *Secret,
	//+optional
	registry string,
	//+optional
	username string,
	//+optional
	image string,
) (string, error) {
	ctr, err := m.BuildContainer(ctx, source)
	if err != nil {
		return "", err
	}

	if registry == "" {
		registry = "ghcr.io"
	}

	if username == "" {
		username = "flipt-io"
	}

	if image == "" {
		image = "reverst"
	}

	return ctr.
		WithRegistryAuth(registry, username, password).
		Publish(ctx, fmt.Sprintf("%s/%s/%s", registry, username, image))
}
