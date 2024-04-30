package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"go.flipt.io/reverst/pkg/protocol"
)

// ErrUnauthorized is returned when the attempted request is not authorized
var ErrUnauthorized = errors.New("unauthorized")

const unauthorizedMsg = "listener request unauthorized"

// HandleBasic performs basic authentication for register listener request metadata
func HandleBasic(username, password string) protocol.AuthenticationHandler {
	expectedUsername := safeComparator(username)
	expectedPassword := safeComparator(password)

	log := slog.With("auth_type", "basic")

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := log.With("tunnel_group", rlr.TunnelGroup)

		cred, err := parseAuthorization(rlr, "Basic ")
		if err != nil {
			log.Info(unauthorizedMsg, "error", err)
			return ErrUnauthorized
		}

		dec, err := base64.StdEncoding.DecodeString(cred)
		if err != nil {
			log.Info(unauthorizedMsg, "error", err)
			return ErrUnauthorized
		}

		username, password, ok := strings.Cut(string(dec), ":")
		if !ok {
			log.Info(unauthorizedMsg, "error", errors.New("missing username:password colon separator"))
			return ErrUnauthorized
		}

		if !(expectedUsername(username) && expectedPassword(password)) {
			log.Info(unauthorizedMsg, "error", errors.New("unexpected username or password"))
			return ErrUnauthorized
		}

		return nil
	})
}

// HandleBearer performs a bearer token comparison for register listener request metadata
func HandleBearer(token string) protocol.AuthenticationHandler {
	expectedToken := safeComparator(token)

	log := slog.With("auth_type", "bearer")

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := log.With("tunnel_group", rlr.TunnelGroup)

		token, err := parseAuthorization(rlr, "Bearer ")
		if err != nil {
			log.Info(unauthorizedMsg, "error", err)
			return ErrUnauthorized
		}

		if !expectedToken(token) {
			log.Info(unauthorizedMsg, "error", errors.New("unexpected token"))
			return ErrUnauthorized
		}

		return nil
	})
}

// HandleBearerHashed performs a bearer token comparison for register listener request metadata
// It expects the token to have been pre-hashed using sha256 and encoded as a hexidecimal string
func HandleBearerHashed(hashedToken string) (protocol.AuthenticationHandler, error) {
	expected, err := hex.DecodeString(hashedToken)
	if err != nil {
		return nil, err
	}

	log := slog.With("auth_type", "bearer_hashed")

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := log.With("tunnel_group", rlr.TunnelGroup)

		token, err := parseAuthorization(rlr, "Bearer ")
		if err != nil {
			log.Info(unauthorizedMsg, "error", err)
			return ErrUnauthorized
		}

		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
			log.Info(unauthorizedMsg, "error", errors.New("unexpected token"))
			return ErrUnauthorized
		}

		return nil
	}), nil
}

func HandleExternalAuthorizer(addr string) (protocol.AuthenticationHandler, error) {
	if _, err := url.Parse(addr); err != nil {
		return nil, fmt.Errorf("building external authorizer: %w", err)
	}

	client := &http.Client{}

	log := slog.With("auth_type", "external")

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := log.With("tunnel_group", rlr.TunnelGroup)

		req, err := http.NewRequest("GET", addr, nil)
		if err != nil {
			return err
		}

		for k, v := range rlr.Metadata {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		body, _ := io.ReadAll(resp.Body)

		log.Info(unauthorizedMsg, "response", string(body), "status", resp.Status)

		return ErrUnauthorized
	}), nil
}

func parseAuthorization(r *protocol.RegisterListenerRequest, expectedScheme string) (string, error) {
	auth, ok := r.Metadata["Authorization"]
	if !ok {
		return "", errors.New("authorization metadata not found")
	}

	if len(auth) < len(expectedScheme) || !strings.EqualFold(auth[:len(expectedScheme)], expectedScheme) {
		return "", errors.New("unexpected authorization scheme")
	}

	return auth[len(expectedScheme):], nil
}

func safeComparator(expected string) func(string) bool {
	expectedSum := sha256.Sum256([]byte(expected))
	return func(presented string) bool {
		presentedSum := sha256.Sum256([]byte(presented))
		return subtle.ConstantTimeCompare(expectedSum[:], presentedSum[:]) == 1
	}
}
