package middleware

import (
	"sync"
	"time"
)

// ObservedToolHashCache is an in-memory cache keyed by (server, tool_name)
// storing the most recently observed tool metadata hash computed from tools/list.
//
// RFA-6fse.4: Used for gateway-owned rug-pull protection without requiring
// client-supplied tool_hash parameters.
type ObservedToolHashCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]observedToolHashEntry
}

type observedToolHashEntry struct {
	Hash       string
	ObservedAt time.Time
}

func observedToolHashKey(server, toolName string) string {
	return server + "|" + toolName
}

// NewObservedToolHashCache creates a cache with the given TTL.
// A zero TTL disables staleness checks (entries never considered stale).
func NewObservedToolHashCache(ttl time.Duration) *ObservedToolHashCache {
	return &ObservedToolHashCache{
		ttl:     ttl,
		entries: make(map[string]observedToolHashEntry),
	}
}

// Get returns (hash, ok, stale).
func (c *ObservedToolHashCache) Get(server, toolName string) (string, bool, bool) {
	if c == nil {
		return "", false, false
	}
	c.mu.RLock()
	entry, ok := c.entries[observedToolHashKey(server, toolName)]
	c.mu.RUnlock()
	if !ok {
		return "", false, false
	}
	if c.ttl > 0 && time.Since(entry.ObservedAt) > c.ttl {
		return entry.Hash, true, true
	}
	return entry.Hash, true, false
}

func (c *ObservedToolHashCache) Set(server, toolName, hash string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries[observedToolHashKey(server, toolName)] = observedToolHashEntry{
		Hash:       hash,
		ObservedAt: time.Now(),
	}
	c.mu.Unlock()
}

func (c *ObservedToolHashCache) SetMany(server string, hashes map[string]string) {
	if c == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	for tool, hash := range hashes {
		c.entries[observedToolHashKey(server, tool)] = observedToolHashEntry{
			Hash:       hash,
			ObservedAt: now,
		}
	}
	c.mu.Unlock()
}
