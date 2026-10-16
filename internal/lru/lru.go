// Package lru provides a small, mutex-protected, size-bounded LRU cache.
//
// Every long-lived map in Pulse that is keyed by attacker- or input-controlled
// data (DNS answers, per-host error counters) goes through this type so that
// memory stays bounded no matter how many targets are processed.
package lru

import (
	"container/list"
	"sync"
)

type entry[K comparable, V any] struct {
	key   K
	value V
}

// Cache is a fixed-capacity LRU map. The zero value is not usable; call New.
type Cache[K comparable, V any] struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[K]*list.Element
}

// New returns a cache that holds at most capacity entries (minimum 1).
func New[K comparable, V any](capacity int) *Cache[K, V] {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache[K, V]{cap: capacity, ll: list.New(), items: make(map[K]*list.Element, min(capacity, 4096))}
}

// Get returns the value for key and marks it most recently used.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*entry[K, V]).value, true
	}
	var zero V
	return zero, false
}

// Set inserts or replaces key, evicting the least recently used entry if full.
func (c *Cache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value)
}

// Update atomically replaces the value of key with fn(old, found).
func (c *Cache[K, V]) Update(key K, fn func(old V, found bool) V) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	var old V
	el, found := c.items[key]
	if found {
		old = el.Value.(*entry[K, V]).value
	}
	v := fn(old, found)
	c.setLocked(key, v)
	return v
}

// Delete removes key if present.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.Remove(el)
		delete(c.items, key)
	}
}

// Len returns the number of entries.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *Cache[K, V]) setLocked(key K, value V) {
	if el, ok := c.items[key]; ok {
		el.Value.(*entry[K, V]).value = value
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&entry[K, V]{key: key, value: value})
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*entry[K, V]).key)
	}
}
