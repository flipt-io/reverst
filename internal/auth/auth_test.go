package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.flipt.io/reverst/pkg/protocol"
)

var (
	basic           = HandleBasic("morty", "gazorpazorp")
	bearer          = HandleBearer("plumbus")
	bearerHashed, _ = HandleBearerHashed("34831eccb70007e3ed06bb8ba0e2c80e661c440d09fb6513c96cd1fdeb5c57cc")
)

func Test_Handlers(t *testing.T) {
	for _, test := range []struct {
		name        string
		handler     protocol.AuthenticationHandler
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
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.handler.Authenticate(&test.request)
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
		require.ErrorIs(t, basic.Authenticate(
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
		require.ErrorIs(t, bearer.Authenticate(
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
		require.ErrorIs(t, bearerHashed.Authenticate(
			&protocol.RegisterListenerRequest{
				TunnelGroup: "sanchez",
				Metadata: map[string]string{
					"Authorization": a,
				},
			},
		), ErrUnauthorized)
	})
}
