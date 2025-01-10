package roundrobbin

import (
	"context"
	"sync"
	"sync/atomic"
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

func Test_Set_RemoveConcurrent(t *testing.T) {
	var (
		a, actx = "a", context.Background()
		b, bctx = "b", context.Background()
	)

	var deleted uint32
	set := Set[string]{
		evicted: func(s string) {
			require.Equal(t, "a", s)
			atomic.AddUint32(&deleted, 1)
		},
	}

	set.Register(actx, a)
	set.Register(bctx, b)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_, ok, err := set.Next(context.Background())
			require.NoError(t, err)
			assert.True(t, ok, "set has become unexpectedly empty")
		}
	}()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set.Remove("a")
		}()
	}

	wg.Wait()

	assert.Equal(t, uint32(1), deleted)
}
