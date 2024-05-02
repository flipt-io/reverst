package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"go.flipt.io/reverst/pkg/protocol"
)

const authorizationMetadataKey = "Authorization"

// Authenticator is a type which adds authentication credentials to an outbound
// register listener request.
// It is called before the request is serialized and written to the stream.
type Authenticator interface {
	Authenticate(context.Context, *protocol.RegisterListenerRequest) error
}

// AuthenticatorFunc is a function which implements the Authenticator interface
type AuthenticatorFunc func(context.Context, *protocol.RegisterListenerRequest) error

// Authenticate delegates to the underlying AuthenticatorFunc
func (a AuthenticatorFunc) Authenticate(ctx context.Context, r *protocol.RegisterListenerRequest) error {
	return a(ctx, r)
}

var defaultAuthenticator Authenticator = AuthenticatorFunc(func(ctx context.Context, rlr *protocol.RegisterListenerRequest) error {
	slog.Warn("No authenticator provided, attempting to register connection without credentials")
	return nil
})

type AuthenticatorOptions struct {
	scheme string
}

type AuthorizationOption func(*AuthenticatorOptions)

func WithScheme(scheme string) AuthorizationOption {
	return func(ao *AuthenticatorOptions) {
		ao.scheme = scheme
	}
}

// BasicAuthenticator returns an instance of Authenticator which configures Basic authentication
// on requests passed to Authenticate using the provided username and password
func BasicAuthenticator(username, password string, opts ...AuthorizationOption) Authenticator {
	options := AuthenticatorOptions{scheme: "Basic"}
	for _, opt := range opts {
		opt(&options)
	}

	return AuthenticatorFunc(func(ctx context.Context, rlr *protocol.RegisterListenerRequest) error {
		if rlr.Metadata == nil {
			rlr.Metadata = map[string]string{}
		}

		rlr.Metadata[authorizationMetadataKey] = fmt.Sprintf("%s %s",
			options.scheme,
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))),
		)

		return nil
	})
}

// BearerAuthenticator returns an instance of Authenticator which configures Bearer authentication
// on requests passed to Authenticate using the provided token string
func BearerAuthenticator(token string, opts ...AuthorizationOption) Authenticator {
	options := AuthenticatorOptions{scheme: "Bearer"}
	for _, opt := range opts {
		opt(&options)
	}

	return AuthenticatorFunc(func(ctx context.Context, rlr *protocol.RegisterListenerRequest) error {
		if rlr.Metadata == nil {
			rlr.Metadata = map[string]string{}
		}

		rlr.Metadata[authorizationMetadataKey] = fmt.Sprintf("%s %s", options.scheme, token)

		return nil
	})
}
