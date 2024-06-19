package auth

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.flipt.io/reverst/pkg/protocol"
)

var (
	basic          = HandleBasic("morty", "gazorpazorp")
	bearer         = HandleBearerSource(StaticBearerSource([]byte("plumbus")))
	hashedToken, _ = HashedStaticBearerSource([]byte("34831eccb70007e3ed06bb8ba0e2c80e661c440d09fb6513c96cd1fdeb5c57cc"))
	bearerHashed   = HandleBearerSource(hashedToken)
	external       Handler
)

func mustHexDecodeString(v string) []byte {
	b, err := hex.DecodeString(v)
	if err != nil {
		panic(err)
	}

	return b
}

func TestMain(m *testing.M) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ext/auth" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}

		if auth := r.Header.Get("Authorization"); auth != "Bearer plumbus" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
		}
	}))
	defer srv.Close()

	external = HandleExternalAuthorizer(fmt.Sprintf("http://%s/ext/auth", srv.Listener.Addr().String()))

	os.Exit(m.Run())
}

func Test_Handlers(t *testing.T) {
	for _, test := range []struct {
		name        string
		handler     Handler
		request     protocol.RegisterListenerRequest
		expectedErr error
	}{
		{
			name:    "basic: matches",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Basic bW9ydHk6Z2F6b3JwYXpvcnA=",
				},
			},
		},
		{
			name:    "basic: missing metadata key",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"WrongKey": "Basic bW9ydHk6Z2F6b3JwYXpvcnA=",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "basic: unexpected scheme",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Unknown bW9ydHk6Z2F6b3JwYXpvcnA=",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "basic: unexpected encoding",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Basic th*s i% n@t b@$£64",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "basic: unexpected form (missing colon)",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Basic bW9ydHlnYXpvcnBhem9ycA==",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "basic: unknown username",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Basic ZXZpbG1vcnR5Om11bHRpdmVyc2U=",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "basic: unknown password",
			handler: basic,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Basic bW9ydHk6bXVsdGl2ZXJzZQ==",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearer: matches",
			handler: bearer,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer plumbus",
				},
			},
		},
		{
			name:    "bearer: missing metadata key",
			handler: bearer,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"WrongKey": "Basic bW9ydHk6Z2F6b3JwYXpvcnA=",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearer: unexpected scheme",
			handler: bearer,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Unknown plumbus",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearer: unknown token",
			handler: bearer,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer wubalubadubdub",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearerHashed: matches",
			handler: bearerHashed,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer plumbus",
				},
			},
		},
		{
			name:    "bearerHashed: missing metadata key",
			handler: bearerHashed,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"WrongKey": "Basic bW9ydHk6Z2F6b3JwYXpvcnA=",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearerHashed: unexpected scheme",
			handler: bearerHashed,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Unknown plumbus",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "bearerHashed: unknown token",
			handler: bearerHashed,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer wubalubadubdub",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "external: matches",
			handler: external,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer plumbus",
				},
			},
		},
		{
			name:    "external: missing metadata key",
			handler: external,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"WrongKey": "Bearer plumbus",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "external: unexpected scheme",
			handler: external,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Unknown plumbus",
				},
			},
			expectedErr: ErrUnauthorized,
		},
		{
			name:    "external: unknown token",
			handler: external,
			request: protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": "Bearer wubalubadubdub",
				},
			},
			expectedErr: ErrUnauthorized,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := Authenticator{
				"Basic":  basic,
				"Bearer": bearer,
				"JWT":    external,
			}

			err := handler.Authenticate(&test.request)
			if test.expectedErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.expectedErr)
		})
	}
}

func FuzzBasic(f *testing.F) {
	f.Add("someunexpectedpayload")
	f.Add("Basic th*s i% n@t b@$£64")
	f.Add("Basic c29tZWludmFsaWQ6Y29tYmluYXRpb24=")
	f.Fuzz(func(t *testing.T, a string) {
		require.ErrorIs(t, Authenticator{"Bearer": basic}.Authenticate(
			&protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": a,
				},
			},
		), ErrUnauthorized)
	})
}

func FuzzBearer(f *testing.F) {
	f.Add("someunexpectedpayload")
	f.Add("Bearer th*s i% n@t b@$£64")
	f.Add("Bearer c29tZWludmFsaWQ6Y29tYmluYXRpb24=")
	f.Fuzz(func(t *testing.T, a string) {
		require.ErrorIs(t, Authenticator{"Bearer": bearer}.Authenticate(
			&protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": a,
				},
			},
		), ErrUnauthorized)
	})
}

func FuzzBearerHashed(f *testing.F) {
	f.Add("someunexpectedpayload")
	f.Add("Bearer th*s i% n@t b@$£64")
	f.Add("Bearer c29tZWludmFsaWQ6Y29tYmluYXRpb24=")
	f.Fuzz(func(t *testing.T, a string) {
		require.ErrorIs(t, Authenticator{"Bearer": bearerHashed}.Authenticate(
			&protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": a,
				},
			},
		), ErrUnauthorized)
	})
}
