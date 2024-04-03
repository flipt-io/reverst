package roundrobbin

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
)

type Set[T comparable] struct {
	mu      sync.RWMutex
	last    atomic.Uint64
	entries []T
}

func (s *Set[T]) Register(ctx context.Context, t T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = append(s.entries, t)

	go func() {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			defer s.mu.Unlock()

			slog.Debug("roundrobbin set: removing entry")

			s.entries = slices.DeleteFunc(s.entries, func(rt T) bool {
				return rt == t
			})
		}
	}()
}

func (s *Set[T]) Next(ctx context.Context) (t T, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.entries) == 0 {
		return t, false
	}

	for {
		if err := ctx.Err(); err != nil {
			return t, false
		}

		var (
			cur  = s.last.Load()
			next = cur + 1
		)
		if next >= uint64(len(s.entries)) {
			next = 0
		}

		if s.last.CompareAndSwap(cur, next) {
			return s.entries[next], true
		}
	}
}
