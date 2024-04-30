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

type Authenticator map[string]Handler

func (a Authenticator) Authenticate(r *protocol.RegisterListenerRequest) error {
	log := slog.With("tunnel_group", r.TunnelGroup)

	if len(a) == 0 {
		log.Debug("No handlers configured skipping authentication")
		return nil
	}

	auth, ok := r.Metadata["Authorization"]
	if !ok {
		log.Info(unauthorizedMsg, "reason", "missing authorization metadata")
		return ErrUnauthorized
	}

	scheme, payload, ok := strings.Cut(strings.TrimSpace(auth), " ")
	if !ok {
		log.Info(unauthorizedMsg, "reason", "malformed authorization payload")
		return ErrUnauthorized
	}

	log = log.With("scheme", scheme)

	handler, ok := a[scheme]
	if !ok {
		log.Info(unauthorizedMsg, "reason", "unsupported scheme")
		return ErrUnauthorized
	}

	if err := handler.Authenticate(scheme, payload); err != nil {
		log.Info(unauthorizedMsg, "reason", err)
		return ErrUnauthorized
	}

	return nil
}

type Handler interface {
	Authenticate(scheme, payload string) error
}

type AuthenticationHandlerFunc func(scheme, payload string) error

func (r AuthenticationHandlerFunc) Authenticate(scheme, payload string) error {
	return r(scheme, payload)
}

// HandleBasic performs basic authentication for register listener request metadata
func HandleBasic(username, password string) Handler {
	expectedUsername := safeComparator(username)
	expectedPassword := safeComparator(password)

	return AuthenticationHandlerFunc(func(scheme, cred string) error {
		if !strings.EqualFold(scheme, "Basic") {
			return fmt.Errorf("basic: unexpected scheme %q", scheme)
		}

		dec, err := base64.StdEncoding.DecodeString(cred)
		if err != nil {
			return fmt.Errorf("basic: decoding credentials: %w", err)
		}

		username, password, ok := strings.Cut(string(dec), ":")
		if !ok {
			return errors.New("basic: unexpected payload format")
		}

		if !(expectedUsername(username) && expectedPassword(password)) {
			return errors.New("basic: username or password unexpected")
		}

		return nil
	})
}

// HandleBearer performs a bearer token comparison for register listener request metadata
func HandleBearer(token string) Handler {
	expectedToken := safeComparator(token)

	return AuthenticationHandlerFunc(func(scheme, token string) error {
		if !strings.EqualFold(scheme, "Bearer") {
			return fmt.Errorf("bearer: unexpected scheme %q", scheme)
		}

		if !expectedToken(token) {
			return errors.New("bearer: token was not expected value")
		}

		return nil
	})
}

// HandleBearerHashed performs a bearer token comparison for register listener request metadata
// It expects the token to have been pre-hashed using sha256 and encoded as a hexidecimal string
func HandleBearerHashed(hashedToken string) (Handler, error) {
	expected, err := hex.DecodeString(hashedToken)
	if err != nil {
		return nil, err
	}

	return AuthenticationHandlerFunc(func(scheme, token string) error {
		if !strings.EqualFold(scheme, "Bearer") {
			return fmt.Errorf("bearer: unexpected scheme %q", scheme)
		}

		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(expected, sum[:]) != 1 {
			return errors.New("bearer: token was not expected value")
		}

		return nil
	}), nil
}

func HandleExternalAuthorizer(addr string) (Handler, error) {
	if _, err := url.Parse(addr); err != nil {
		return nil, fmt.Errorf("building external authorizer: %w", err)
	}

	client := &http.Client{}

	return AuthenticationHandlerFunc(func(scheme, payload string) error {
		req, err := http.NewRequest("GET", addr, nil)
		if err != nil {
			return err
		}

		req.Header.Set("Authorization", fmt.Sprintf("%s %s", scheme, payload))

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("external: unexpected response (status %d) %q", resp.StatusCode, string(body))
	}), nil
}

func safeComparator(expected string) func(string) bool {
	expectedSum := sha256.Sum256([]byte(expected))
	return func(presented string) bool {
		presentedSum := sha256.Sum256([]byte(presented))
		return subtle.ConstantTimeCompare(expectedSum[:], presentedSum[:]) == 1
	}
}
