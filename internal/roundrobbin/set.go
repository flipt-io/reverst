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
	evicted func(T)
}

func WithOnEvict[T comparable](fn func(T)) func(*Set[T]) {
	return func(s *Set[T]) {
		s.evicted = fn
	}
}

func NewSet[T comparable](opts ...func(*Set[T])) *Set[T] {
	set := &Set[T]{}

	for _, opt := range opts {
		opt(set)
	}

	return set
}

func (s *Set[T]) Register(ctx context.Context, t T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = append(s.entries, t)

	// start a goroutine which removes the instance from the set
	// when the context is closed
	go func() {
		select {
		case <-ctx.Done():
			s.Remove(t)
		}
	}()
}

func (s *Set[T]) Remove(t T) {
	var evicted bool

	s.mu.Lock()
	defer func() {
		s.mu.Unlock()

		if s.evicted != nil && evicted {
			s.evicted(t)
		}
	}()

	slog.Debug("roundrobbin set: removing entry")

	s.entries = slices.DeleteFunc(s.entries, func(rt T) bool {
		evicted = evicted || rt == t
		return rt == t
	})
}

func (s *Set[T]) Next(ctx context.Context) (t T, ok bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.entries) == 0 {
		return t, false, nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return t, false, err
		}

		var (
			observed = s.last.Load()
			cur      = observed
			count    = uint64(len(s.entries))
		)

		if cur >= count {
			cur = 0
		}

		next := cur + 1
		if next >= count {
			next = 0
		}

		if s.last.CompareAndSwap(observed, next) {
			return s.entries[cur], true, nil
		}
	}
}
