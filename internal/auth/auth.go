package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"

	"go.flipt.io/reverst/internal/protocol"
)

// ErrUnauthorized is returned when the attempted request is not authorized
var ErrUnauthorized = errors.New("unauthorized")

const unauthorizedMsg = "listener request unauthorized"

// HandleBasic performs basic authentication for register listener request metadata
func HandleBasic(username, password string) protocol.AuthenticationHandler {
	expectedUsername := safeComparator(username)
	expectedPassword := safeComparator(password)

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := slog.With("tunnel_group", rlr.TunnelGroup)

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

	return protocol.AuthenticationHandlerFunc(func(rlr *protocol.RegisterListenerRequest) error {
		log := slog.With("tunnel_group", rlr.TunnelGroup)

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
