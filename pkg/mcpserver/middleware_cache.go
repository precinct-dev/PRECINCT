// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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

// cacheResult holds the result of a cache lookup, including the remaining
// TTL for the entry (zero on a miss).
type cacheResult struct {
	value        any
	hit          bool
	ttlRemaining time.Duration
}

// get retrieves a cached result if it exists and has not expired. Returns
// a cacheResult with hit=true and the remaining TTL on a hit, or hit=false
// on a miss or expired entry.
func (c *responseCache) get(key string) cacheResult {
	v, ok := c.entries.Load(key)
	if !ok {
		return cacheResult{}
	}
	entry := v.(cacheEntry)
	remaining := time.Until(entry.expires)
	if remaining <= 0 {
		c.entries.Delete(key)
		return cacheResult{}
	}
	return cacheResult{value: entry.result, hit: true, ttlRemaining: remaining}
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
// the arguments map. If a tracer is provided via withCacheTracer, each
// evaluation creates a child span "middleware.cache" with mcp.cache.hit
// (bool) and mcp.cache.ttl_remaining_s (float64) attributes.
func newCacheMiddleware(ttl time.Duration, opts ...cacheOption) Middleware {
	cfg := cacheConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	cache := newResponseCache(ttl)
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			toolName := ToolNameFromContext(ctx)
			key := cacheKey(toolName, args)

			cr := cache.get(key)
			if cr.hit {
				if cfg.tracer != nil {
					_, span := cfg.tracer.Start(ctx, "middleware.cache",
						trace.WithSpanKind(trace.SpanKindInternal))
					span.SetAttributes(
						attribute.Bool("mcp.cache.hit", true),
						attribute.Float64("mcp.cache.ttl_remaining_s", cr.ttlRemaining.Seconds()),
					)
					span.End()
				}
				return cr.value, nil
			}

			result, err := next(ctx, args)
			if err != nil {
				if cfg.tracer != nil {
					_, span := cfg.tracer.Start(ctx, "middleware.cache",
						trace.WithSpanKind(trace.SpanKindInternal))
					span.SetAttributes(
						attribute.Bool("mcp.cache.hit", false),
						attribute.Float64("mcp.cache.ttl_remaining_s", 0),
					)
					span.End()
				}
				return result, err
			}

			cache.set(key, result)

			if cfg.tracer != nil {
				_, span := cfg.tracer.Start(ctx, "middleware.cache",
					trace.WithSpanKind(trace.SpanKindInternal))
				span.SetAttributes(
					attribute.Bool("mcp.cache.hit", false),
					attribute.Float64("mcp.cache.ttl_remaining_s", ttl.Seconds()),
				)
				span.End()
			}

			return result, nil
		}
	}
}

// cacheConfig holds optional configuration for the cache middleware.
type cacheConfig struct {
	tracer trace.Tracer
}

// cacheOption configures the cache middleware.
type cacheOption func(*cacheConfig)

// withCacheTracer sets the OTel tracer for the cache middleware.
func withCacheTracer(t trace.Tracer) cacheOption {
	return func(c *cacheConfig) {
		c.tracer = t
	}
}
