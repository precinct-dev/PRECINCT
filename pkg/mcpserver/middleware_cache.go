package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// defaultCacheTTL is the default time-to-live for cached tool responses.
const defaultCacheTTL = 5 * time.Minute

// cacheEntry holds a cached result along with its expiry timestamp.
type cacheEntry struct {
	result  any
	expires time.Time
}

// responseCache is a concurrency-safe, in-memory cache keyed by a hash of
// the tool name and arguments. It uses sync.Map for lock-free reads on the
// hot path and applies TTL-based expiry at lookup time (lazy eviction).
type responseCache struct {
	entries sync.Map // string -> cacheEntry
	ttl     time.Duration
}

// newResponseCache creates a new responseCache with the given TTL.
func newResponseCache(ttl time.Duration) *responseCache {
	return &responseCache{ttl: ttl}
}

// cacheKey produces a deterministic key from the tool name and arguments.
// It serializes the arguments to sorted JSON, then hashes the result with
// SHA-256 to keep key length bounded.
func cacheKey(toolName string, args map[string]any) string {
	b, _ := json.Marshal(args) // nil/empty maps marshal cleanly
	h := sha256.Sum256(append([]byte(toolName+":"), b...))
	return fmt.Sprintf("%x", h)
}

// get retrieves a cached result if it exists and has not expired. The
// second return value indicates whether a valid entry was found.
func (c *responseCache) get(key string) (any, bool) {
	v, ok := c.entries.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(cacheEntry)
	if time.Now().After(entry.expires) {
		c.entries.Delete(key)
		return nil, false
	}
	return entry.result, true
}

// set stores a result in the cache with the configured TTL.
func (c *responseCache) set(key string, result any) {
	c.entries.Store(key, cacheEntry{
		result:  result,
		expires: time.Now().Add(c.ttl),
	})
}

// newCacheMiddleware returns a Middleware that caches successful tool
// responses. Errors are never cached. The cache is keyed by a hash of
// the tool name (injected into context by the context middleware) and
// the arguments map.
func newCacheMiddleware(ttl time.Duration) Middleware {
	cache := newResponseCache(ttl)
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			toolName := ToolNameFromContext(ctx)
			key := cacheKey(toolName, args)

			if cached, ok := cache.get(key); ok {
				return cached, nil
			}

			result, err := next(ctx, args)
			if err != nil {
				return result, err
			}

			cache.set(key, result)
			return result, nil
		}
	}
}
