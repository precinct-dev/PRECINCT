// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// UI Resource Cache - RFA-j2d.2
// Thread-safe in-memory cache for ui:// resource content with hash-based
// integrity verification. Detects content changes (rug-pull attacks) by
// comparing SHA-256 hashes across reads.
//
// Reference Architecture Section 7.9.3: Caching and integrity.
//
// Cache key: (server, resourceUri) -> CacheEntry{contentHash, content, metadata}
// On subsequent reads: if content hash changed from cached baseline, the
// resource is blocked and a critical alert is emitted (analogous to tool
// description rug-pull detection in the tool registry).
package gateway

import (
	"sync"
	"time"
)

// UIResourceCacheEntry holds a cached ui:// resource with its integrity metadata.
type UIResourceCacheEntry struct {
	Server      string    `json:"server"`
	ResourceURI string    `json:"resource_uri"`
	ContentHash string    `json:"content_hash"` // SHA-256 hex
	Content     []byte    `json:"-"`            // Not serialized to JSON (may be large)
	CachedAt    time.Time `json:"cached_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	HitCount    int64     `json:"hit_count"` // Number of cache hits
}

// Expired returns true if the cache entry has passed its TTL.
func (e *UIResourceCacheEntry) Expired() bool {
	return time.Now().After(e.ExpiresAt)
}

// UIResourceCache is a thread-safe in-memory cache for ui:// resource content.
// Entries are keyed by (server, resourceURI) and include the content hash
// for integrity verification.
type UIResourceCache struct {
	mu        sync.RWMutex
	entries   map[string]*UIResourceCacheEntry // cacheKey -> entry
	ttl       time.Duration
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewUIResourceCache creates a new cache with the given TTL.
// Starts a background goroutine to evict expired entries every 60 seconds.
func NewUIResourceCache(ttl time.Duration) *UIResourceCache {
	c := &UIResourceCache{
		entries: make(map[string]*UIResourceCacheEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// cacheKey builds the lookup key from server and resourceURI.
func cacheKey(server, resourceURI string) string {
	return server + "|" + resourceURI
}

// Get retrieves a cache entry for the given (server, resourceURI).
// Returns nil if no entry exists or the entry has expired.
// Expired entries are removed on access.
func (c *UIResourceCache) Get(server, resourceURI string) *UIResourceCacheEntry {
	key := cacheKey(server, resourceURI)

	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return nil
	}

	if entry.Expired() {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}

	// Increment hit count (best-effort, no lock upgrade needed for stats)
	c.mu.Lock()
	entry.HitCount++
	c.mu.Unlock()

	return entry
}

// Put stores or updates a cache entry for the given (server, resourceURI).
// The content hash is stored alongside the content for integrity verification.
func (c *UIResourceCache) Put(server, resourceURI, contentHash string, content []byte) {
	key := cacheKey(server, resourceURI)
	now := time.Now()

	// Make a copy of content to avoid retaining the caller's buffer
	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)

	entry := &UIResourceCacheEntry{
		Server:      server,
		ResourceURI: resourceURI,
		ContentHash: contentHash,
		Content:     contentCopy,
		CachedAt:    now,
		ExpiresAt:   now.Add(c.ttl),
		HitCount:    0,
	}

	c.mu.Lock()
	c.entries[key] = entry
	c.mu.Unlock()
}

// Delete removes a cache entry.
func (c *UIResourceCache) Delete(server, resourceURI string) {
	key := cacheKey(server, resourceURI)
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// Count returns the number of entries in the cache (including expired).
func (c *UIResourceCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (c *UIResourceCache) Close() {
	c.closeOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
	})
}

// cleanupLoop periodically removes expired entries.
func (c *UIResourceCache) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.evictExpired()
		case <-c.stopCh:
			return
		}
	}
}

// evictExpired removes all expired entries.
func (c *UIResourceCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

// CheckHashMismatch compares the provided content hash against the cached
// entry for the given (server, resourceURI). Returns:
//   - (true, expectedHash) if there IS a mismatch (rug-pull detected)
//   - (false, "") if no mismatch or no cached entry
func (c *UIResourceCache) CheckHashMismatch(server, resourceURI, currentHash string) (bool, string) {
	entry := c.Get(server, resourceURI)
	if entry == nil {
		return false, ""
	}
	if entry.ContentHash != currentHash {
		return true, entry.ContentHash
	}
	return false, ""
}
