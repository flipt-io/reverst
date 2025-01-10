package config

import (
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_k8sSource_watchConfigMap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(newTestWriter(t), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	slog.SetDefault(logger)

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		clientset   = fake.NewSimpleClientset(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "reverst",
					Namespace: "default",
					Labels:    map[string]string{},
				},
				Data: map[string]string{
					"groups.yml": mustMarshal(t, map[string]any{
						"groups": map[string]any{
							"localhost": map[string]any{
								"hosts": []string{"localhost"},
								"authentication": map[string]any{
									"basic": map[string]any{"username": "user", "password": "pass"},
								},
							},
						},
					}),
				},
			},
		)
	)
	t.Cleanup(cancel)

	t.Log("Created clientset")

	var (
		src    = newK8sSourceForClientset(ctx, clientset)
		groups = make(chan *TunnelGroups)
	)

	t.Log("Created k8s source")

	err := src.watchConfigMap(ctx, groups, "default", "reverst", "groups.yml")
	require.NoError(t, err)

	t.Log("Started watcher")

	expected := &TunnelGroups{
		Groups: map[string]TunnelGroup{
			"localhost": {
				Hosts: []string{"localhost"},
				Authentication: TunnelGroupAuthentication{
					Basic: &AuthenticationBasic{
						Scheme:   "Basic",
						Username: "user",
						Password: "pass",
					},
				},
			},
		},
	}
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for group")
	case group := <-groups:
		assert.Equal(t, expected, group)
	}
}

func Test_k8sSource_secretBearerSource(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(newTestWriter(t), &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	slog.SetDefault(logger)

	var (
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		clientset   = fake.NewSimpleClientset(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "credentials",
					Labels:    map[string]string{},
				},
				Data: map[string][]byte{
					"token": []byte("sometokenvalue"),
				},
			},
		)
	)
	t.Cleanup(cancel)

	t.Log("Created clientset")

	src := newK8sSourceForClientset(ctx, clientset)

	t.Log("Created k8s source")

	bearerSource, err := src.newSecretBearerSource(ctx, "default", "credentials", "token", false)
	require.NoError(t, err)

	token, err := bearerSource.GetCredential()
	require.NoError(t, err)

	expected := sha256.Sum256([]byte("sometokenvalue"))
	assert.Equal(t, expected[:], token)

	updated := make(chan struct{})
	bearerSource.informer.AddEventHandler(TypedEventHandler[*corev1.Secret]{
		UpdateFunc: func(s1, s2 *corev1.Secret) {
			close(updated)
		},
	})

	_, err = clientset.CoreV1().Secrets("default").Update(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "credentials",
			Labels:    map[string]string{},
		},
		Data: map[string][]byte{
			"token": []byte("somenewtokenvalue"),
		},
	}, metav1.UpdateOptions{})
	require.NoError(t, err)

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for secret update")
	case <-updated:
	}

	token, err = bearerSource.GetCredential()
	require.NoError(t, err)

	expected = sha256.Sum256([]byte("somenewtokenvalue"))
	assert.Equal(t, expected[:], token)
}

func mustMarshal(t *testing.T, v map[string]any) string {
	t.Helper()

	m, err := yaml.Marshal(v)
	require.NoError(t, err)

	return string(m)
}

type testWriter struct {
	t *testing.T

	mu  sync.Mutex
	err error
}

func newTestWriter(t *testing.T) *testWriter {
	t.Helper()
	wr := &testWriter{t: t}
	t.Cleanup(func() {
		wr.mu.Lock()
		wr.err = io.EOF
		wr.mu.Unlock()
	})
	return wr
}

func (t *testWriter) Write(v []byte) (int, error) {
	t.t.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.err != nil {
		return 0, t.err
	}

	t.t.Log(strings.TrimSpace(string(v)))
	return len(v), nil
}
