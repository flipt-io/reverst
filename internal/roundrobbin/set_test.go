package roundrobbin

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Set(t *testing.T) {
	var (
		a, actx = "a", context.Background()
		b, bctx = "b", context.Background()
		c, cctx = "c", context.Background()
		d, dctx = "d", context.Background()
	)

	var set Set[string]

	set.Register(actx, a)
	set.Register(bctx, b)

	cctx, ccancel := context.WithCancel(cctx)
	set.Register(cctx, c)

	set.Register(dctx, d)

	var (
		expected = []string{"a", "b", "c", "d", "a", "b", "c", "d"}
		found    []string
	)

	for range expected {
		v, ok, err := set.Next(context.Background())
		require.NoError(t, err)
		require.True(t, ok, "value unexpectedly not found")
		found = append(found, v)
	}

	assert.Equal(t, expected, found)

	evicted := make(chan string)
	set.evicted = func(s string) {
		evicted <- s
	}

	ccancel()

	select {
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for eviction")
	case <-evicted:
	}

	expected = []string{"a", "b", "d", "a", "b", "d"}
	found = []string{}

	for range expected {
		v, ok, err := set.Next(context.Background())
		require.NoError(t, err)
		require.True(t, ok, "value unexpectedly not found")
		found = append(found, v)
	}

	assert.Equal(t, expected, found)
}
