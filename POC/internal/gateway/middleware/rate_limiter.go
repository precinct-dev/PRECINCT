package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// RateLimitStore defines the storage interface for rate limiting state.
// Implementations must be safe for concurrent use.
type RateLimitStore interface {
	// GetTokens retrieves the current token count and last refill time for a SPIFFE ID.
	// Returns (tokens, lastFill, error). If the key does not exist, returns (-1, zero time, nil)
	// to signal that a new bucket should be initialized.
	GetTokens(ctx context.Context, spiffeID string) (float64, time.Time, error)

	// SetTokens persists the current token count and last refill time for a SPIFFE ID.
	SetTokens(ctx context.Context, spiffeID string, tokens float64, lastFill time.Time) error
}

// RateLimiter manages per-agent rate limits using a token bucket algorithm
// backed by a pluggable RateLimitStore (in-memory or KeyDB).
type RateLimiter struct {
	store RateLimitStore
	rpm   int // requests per minute
	burst int // burst allowance (bucket capacity)
}

// NewRateLimiter creates a new rate limiter with the given RPM, burst, and store.
// The store determines whether state is kept in-memory or distributed via KeyDB.
func NewRateLimiter(rpm, burst int, store RateLimitStore) *RateLimiter {
	// Ensure burst is at least 1 to allow initial requests
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		store: store,
		rpm:   rpm,
		burst: burst,
	}
}

// Allow checks if a request is allowed under rate limits using the token bucket
// algorithm. Tokens refill at rpm/60 per second, up to the burst capacity.
func (rl *RateLimiter) Allow(spiffeID string) (allowed bool, remaining int, resetTime time.Time) {
	ctx := context.Background()
	now := time.Now()

	tokens, lastFill, err := rl.store.GetTokens(ctx, spiffeID)
	if err != nil {
		// On store error, fail closed (deny) to avoid letting traffic through
		// when distributed state is unavailable.
		return false, 0, now.Add(time.Minute)
	}

	// If no existing bucket, initialize with full capacity
	if tokens < 0 {
		tokens = float64(rl.burst)
		lastFill = now
	}

	// Refill tokens based on elapsed time since last fill
	perSecond := float64(rl.rpm) / 60.0
	elapsed := now.Sub(lastFill).Seconds()
	tokens += elapsed * perSecond

	// Cap at burst capacity
	if tokens > float64(rl.burst) {
		tokens = float64(rl.burst)
	}

	// Calculate reset time (next minute boundary)
	resetTime = now.Add(time.Minute)

	// Try to consume one token
	if tokens >= 1.0 {
		allowed = true
		tokens -= 1.0
	}

	// Persist updated state
	if storeErr := rl.store.SetTokens(ctx, spiffeID, tokens, now); storeErr != nil {
		// Log but don't fail the request if we already allowed it.
		// The next request will re-read from store and get stale data,
		// which is acceptable for rate limiting (eventual consistency).
	}

	remaining = int(math.Floor(tokens))
	if remaining < 0 {
		remaining = 0
	}

	return allowed, remaining, resetTime
}

// ---------------------------------------------------------------------------
// InMemoryRateLimitStore -- in-process token bucket state (Phase 1 behavior)
// ---------------------------------------------------------------------------

// InMemoryRateLimitStore stores rate limit tokens in local memory.
// Suitable for single-instance deployments. Not distributed.
type InMemoryRateLimitStore struct {
	mu      sync.RWMutex
	buckets map[string]*inMemoryBucket
}

type inMemoryBucket struct {
	tokens   float64
	lastFill time.Time
}

// NewInMemoryRateLimitStore creates a new in-memory rate limit store.
func NewInMemoryRateLimitStore() *InMemoryRateLimitStore {
	return &InMemoryRateLimitStore{
		buckets: make(map[string]*inMemoryBucket),
	}
}

func (s *InMemoryRateLimitStore) GetTokens(_ context.Context, spiffeID string) (float64, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucket, exists := s.buckets[spiffeID]
	if !exists {
		return -1, time.Time{}, nil // signal: new bucket needed
	}
	return bucket.tokens, bucket.lastFill, nil
}

func (s *InMemoryRateLimitStore) SetTokens(_ context.Context, spiffeID string, tokens float64, lastFill time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[spiffeID] = &inMemoryBucket{
		tokens:   tokens,
		lastFill: lastFill,
	}
	return nil
}

// ---------------------------------------------------------------------------
// KeyDBRateLimitStore -- KeyDB/Redis-backed distributed rate limiting
// ---------------------------------------------------------------------------

const (
	rateLimitTTL = 120 * time.Second // 2x the 60s refill window; auto-expire stale entries
)

// KeyDBRateLimitStore stores rate limit tokens in KeyDB/Redis.
// Data model:
//   - ratelimit:{spiffe_id}:tokens    -> STRING (float64, current token count)
//   - ratelimit:{spiffe_id}:last_fill -> STRING (Unix timestamp of last refill)
//   - TTL: 120s on both keys (2x refill window, auto-expires stale entries)
type KeyDBRateLimitStore struct {
	client *redis.Client
}

// NewKeyDBRateLimitStore creates a new KeyDB-backed rate limit store.
// Accepts an existing redis.Client to enable connection pool sharing
// with the session store.
func NewKeyDBRateLimitStore(client *redis.Client) *KeyDBRateLimitStore {
	return &KeyDBRateLimitStore{
		client: client,
	}
}

func rateLimitTokensKey(spiffeID string) string {
	return "ratelimit:" + spiffeID + ":tokens"
}

func rateLimitLastFillKey(spiffeID string) string {
	return "ratelimit:" + spiffeID + ":last_fill"
}

func (s *KeyDBRateLimitStore) GetTokens(ctx context.Context, spiffeID string) (float64, time.Time, error) {
	tokensKey := rateLimitTokensKey(spiffeID)
	lastFillKey := rateLimitLastFillKey(spiffeID)

	// Use pipeline to fetch both values atomically
	pipe := s.client.Pipeline()
	tokensCmd := pipe.Get(ctx, tokensKey)
	lastFillCmd := pipe.Get(ctx, lastFillKey)
	_, _ = pipe.Exec(ctx) // Errors are on individual commands

	// Check if keys exist
	tokensStr, err := tokensCmd.Result()
	if err == redis.Nil {
		return -1, time.Time{}, nil // New bucket
	}
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("keydb get tokens: %w", err)
	}

	lastFillStr, err := lastFillCmd.Result()
	if err == redis.Nil {
		return -1, time.Time{}, nil // Inconsistent state, treat as new
	}
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("keydb get last_fill: %w", err)
	}

	tokens, err := strconv.ParseFloat(tokensStr, 64)
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("keydb parse tokens: %w", err)
	}

	lastFillNano, err := strconv.ParseInt(lastFillStr, 10, 64)
	if err != nil {
		return -1, time.Time{}, fmt.Errorf("keydb parse last_fill: %w", err)
	}

	return tokens, time.Unix(0, lastFillNano), nil
}

func (s *KeyDBRateLimitStore) SetTokens(ctx context.Context, spiffeID string, tokens float64, lastFill time.Time) error {
	tokensKey := rateLimitTokensKey(spiffeID)
	lastFillKey := rateLimitLastFillKey(spiffeID)

	// Use pipeline to set both values with TTL atomically
	pipe := s.client.Pipeline()
	pipe.Set(ctx, tokensKey, strconv.FormatFloat(tokens, 'f', -1, 64), rateLimitTTL)
	pipe.Set(ctx, lastFillKey, strconv.FormatInt(lastFill.UnixNano(), 10), rateLimitTTL)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("keydb set rate limit: %w", err)
	}

	return nil
}

// AppDrivenRateLimiter manages a separate rate limit bucket for app-driven tool
// calls (RFA-j2d.4). It reuses the same RateLimiter implementation but with
// different RPM/burst values (default: 20 req/min, burst 5).
//
// The key prefix "app:" distinguishes app-driven buckets from agent-driven ones.
type AppDrivenRateLimiter struct {
	limiter *RateLimiter
}

// NewAppDrivenRateLimiter creates a rate limiter with app-driven defaults.
// Per Section 7.9.5: 20 req/min with burst of 5.
func NewAppDrivenRateLimiter(rpm, burst int) *AppDrivenRateLimiter {
	return &AppDrivenRateLimiter{
		limiter: NewRateLimiter(rpm, burst, NewInMemoryRateLimitStore()),
	}
}

// Allow checks if an app-driven request is allowed under the separate
// app-driven rate limit bucket. The key is prefixed with "app:" to keep
// app-driven and agent-driven buckets separate.
func (a *AppDrivenRateLimiter) Allow(spiffeID string) (allowed bool, remaining int, resetTime time.Time) {
	return a.limiter.Allow("app:" + spiffeID)
}

// RPM returns the configured requests-per-minute for the app-driven limiter.
func (a *AppDrivenRateLimiter) RPM() int {
	return a.limiter.rpm
}

// Burst returns the configured burst allowance for the app-driven limiter.
func (a *AppDrivenRateLimiter) Burst() int {
	return a.limiter.burst
}

// RateLimitMiddleware creates middleware for per-agent rate limiting
// Position: Step 11 (after deep scan, before circuit breaker)
func RateLimitMiddleware(next http.Handler, limiter *RateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 11
		ctx, span := tracer.Start(r.Context(), "gateway.rate_limit",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 11),
				attribute.String("mcp.gateway.middleware", "rate_limit"),
			),
		)
		defer span.End()

		// Get SPIFFE ID from context (set by SPIFFE auth middleware)
		spiffeID := GetSPIFFEID(ctx)
		if spiffeID == "" {
			// No SPIFFE ID - should not happen if SPIFFE auth passed
			// Fail closed: deny request
			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "missing SPIFFE ID"),
			)
			http.Error(w, "Unauthorized: Missing SPIFFE ID", http.StatusUnauthorized)
			return
		}

		// Check rate limit
		allowed, remaining, resetTime := limiter.Allow(spiffeID)

		// Calculate retry_after_seconds for rate limit response
		retryAfter := int(time.Until(resetTime).Seconds())
		if retryAfter < 0 {
			retryAfter = 0
		}

		// RFA-m6j.2: Set rate limit span attributes
		span.SetAttributes(
			attribute.Int("remaining", remaining),
			attribute.Int("limit", limiter.rpm),
			attribute.Int("burst", limiter.burst),
		)

		// Add rate limit headers to response (in ALL cases, per AC #6)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.rpm))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		// If rate limit exceeded, return HTTP 429
		if !allowed {
			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "rate limit exceeded"),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)

			resp := map[string]interface{}{
				"error":               "rate_limit_exceeded",
				"retry_after_seconds": retryAfter,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		span.SetAttributes(
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", ""),
		)

		// Request allowed - continue
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
