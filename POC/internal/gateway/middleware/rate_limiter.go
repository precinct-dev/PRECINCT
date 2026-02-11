package middleware

import (
	"context"
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

	// Guard against races when the underlying store does not provide an atomic
	// token-consumption primitive (e.g., in-memory store). KeyDB uses an atomic
	// Lua script, so this is only used as a fallback.
	locks sync.Map // map[string]*sync.Mutex keyed by SPIFFE ID
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

func (rl *RateLimiter) lockFor(spiffeID string) *sync.Mutex {
	if spiffeID == "" {
		// Should never happen; callers already enforce SPIFFE ID presence.
		return &sync.Mutex{}
	}
	if v, ok := rl.locks.Load(spiffeID); ok {
		return v.(*sync.Mutex)
	}
	mu := &sync.Mutex{}
	actual, _ := rl.locks.LoadOrStore(spiffeID, mu)
	return actual.(*sync.Mutex)
}

// Allow checks if a request is allowed under rate limits using the token bucket
// algorithm. Tokens refill at rpm/60 per second, up to the burst capacity.
func (rl *RateLimiter) Allow(spiffeID string) (allowed bool, remaining int, resetTime time.Time) {
	ctx := context.Background()
	now := time.Now()

	// Distributed KeyDB store: use an atomic Lua script to avoid lost updates
	// under concurrency and across gateway replicas.
	if keydbStore, ok := rl.store.(*KeyDBRateLimitStore); ok {
		allowed, remaining, err := keydbStore.TakeTokenAtomic(ctx, spiffeID, rl.rpm, rl.burst, now)
		if err != nil {
			// On store error, fail closed (deny) to avoid letting traffic through
			// when distributed state is unavailable.
			return false, 0, now.Add(time.Minute)
		}
		resetTime = now.Add(time.Minute)
		return allowed, remaining, resetTime
	}

	// Non-atomic stores: serialize per SPIFFE ID to avoid lost updates.
	mu := rl.lockFor(spiffeID)
	mu.Lock()
	defer mu.Unlock()

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

	// Persist updated state best-effort. A stale token write only impacts
	// short-term precision and is acceptable for this limiter design.
	_ = rl.store.SetTokens(ctx, spiffeID, tokens, now)

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

var takeTokenLua = redis.NewScript(`
-- KEYS[1] = tokensKey
-- KEYS[2] = lastFillKey
-- ARGV[1] = now_unix_nano
-- ARGV[2] = rpm
-- ARGV[3] = burst
-- ARGV[4] = ttl_seconds

local now = tonumber(ARGV[1])
local rpm = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local tokensStr = redis.call("GET", KEYS[1])
local lastStr = redis.call("GET", KEYS[2])

local tokens
local last
if (not tokensStr) or (not lastStr) then
  tokens = burst
  last = now
else
  tokens = tonumber(tokensStr)
  last = tonumber(lastStr)
end

local perSecond = rpm / 60.0
local elapsed = (now - last) / 1000000000.0
if elapsed < 0 then
  elapsed = 0
end

tokens = tokens + (elapsed * perSecond)
if tokens > burst then
  tokens = burst
end

local allowed = 0
if tokens >= 1.0 then
  allowed = 1
  tokens = tokens - 1.0
end

redis.call("SETEX", KEYS[1], ttl, tostring(tokens))
redis.call("SETEX", KEYS[2], ttl, tostring(now))

return {allowed, math.floor(tokens)}
`)

// NewKeyDBRateLimitStore creates a new KeyDB-backed rate limit store.
// Accepts an existing redis.Client to enable connection pool sharing
// with the session store.
func NewKeyDBRateLimitStore(client *redis.Client) *KeyDBRateLimitStore {
	return &KeyDBRateLimitStore{
		client: client,
	}
}

// TakeTokenAtomic atomically refills and consumes a single token for the given
// SPIFFE ID using a KeyDB Lua script. This avoids lost updates under concurrency.
func (s *KeyDBRateLimitStore) TakeTokenAtomic(ctx context.Context, spiffeID string, rpm, burst int, now time.Time) (bool, int, error) {
	tokensKey := rateLimitTokensKey(spiffeID)
	lastFillKey := rateLimitLastFillKey(spiffeID)

	res, err := takeTokenLua.Run(ctx, s.client,
		[]string{tokensKey, lastFillKey},
		now.UnixNano(),
		rpm,
		burst,
		int(rateLimitTTL.Seconds()),
	).Result()
	if err != nil {
		return false, 0, fmt.Errorf("keydb eval rate limit: %w", err)
	}

	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("keydb eval rate limit: unexpected result type %T", res)
	}

	allowedNum, ok1 := arr[0].(int64)
	remainingNum, ok2 := arr[1].(int64)
	if !ok1 || !ok2 {
		// Some redis impls may return strings; try to coerce.
		allowedStr, okA := arr[0].(string)
		remainingStr, okR := arr[1].(string)
		if okA && okR {
			a, errA := strconv.ParseInt(allowedStr, 10, 64)
			r, errR := strconv.ParseInt(remainingStr, 10, 64)
			if errA == nil && errR == nil {
				return a == 1, int(r), nil
			}
		}
		return false, 0, fmt.Errorf("keydb eval rate limit: unexpected result elements %T/%T", arr[0], arr[1])
	}

	return allowedNum == 1, int(remainingNum), nil
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
			WriteGatewayError(w, r.WithContext(ctx), http.StatusUnauthorized, GatewayError{
				Code:           ErrAuthMissingIdentity,
				Message:        "Missing SPIFFE ID for rate limiting",
				Middleware:     "rate_limit",
				MiddlewareStep: 11,
			})
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
			WriteGatewayError(w, r.WithContext(ctx), http.StatusTooManyRequests, GatewayError{
				Code:           ErrRateLimitExceeded,
				Message:        "Rate limit exceeded",
				Middleware:     "rate_limit",
				MiddlewareStep: 11,
				Details: map[string]any{
					"retry_after_seconds": retryAfter,
					"limit":               limiter.rpm,
					"remaining":           0,
				},
				Remediation: fmt.Sprintf("Wait %d seconds before retrying.", retryAfter),
			})
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
