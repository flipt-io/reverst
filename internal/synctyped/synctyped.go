package synctyped

import "sync"

type Map[T any] struct {
	sync.Map
}

func (m *Map[T]) Store(k string, t T) {
	m.Map.Store(k, t)
}

func (m *Map[T]) Load(k string) (t T, ok bool) {
	v, ok := m.Map.Load(k)
	if !ok {
		return t, ok
	}

	return v.(T), true
}
