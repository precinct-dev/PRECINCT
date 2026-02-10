package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// InMemoryRateLimitStore Tests
// ---------------------------------------------------------------------------

func TestInMemoryRateLimitStore_GetTokens_NotFound(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	ctx := context.Background()

	tokens, lastFill, err := store.GetTokens(ctx, "spiffe://test/agent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if tokens != -1 {
		t.Errorf("Expected tokens=-1 for nonexistent key, got %f", tokens)
	}
	if !lastFill.IsZero() {
		t.Errorf("Expected zero lastFill for nonexistent key, got %v", lastFill)
	}
}

func TestInMemoryRateLimitStore_SetAndGetTokens(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	now := time.Now()

	if err := store.SetTokens(ctx, spiffeID, 5.5, now); err != nil {
		t.Fatalf("SetTokens error: %v", err)
	}

	tokens, lastFill, err := store.GetTokens(ctx, spiffeID)
	if err != nil {
		t.Fatalf("GetTokens error: %v", err)
	}
	if tokens != 5.5 {
		t.Errorf("Expected tokens=5.5, got %f", tokens)
	}
	if !lastFill.Equal(now) {
		t.Errorf("Expected lastFill=%v, got %v", now, lastFill)
	}
}

func TestInMemoryRateLimitStore_PerAgentIsolation(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	ctx := context.Background()

	now := time.Now()
	_ = store.SetTokens(ctx, "agent-1", 10.0, now)
	_ = store.SetTokens(ctx, "agent-2", 3.0, now)

	tokens1, _, _ := store.GetTokens(ctx, "agent-1")
	tokens2, _, _ := store.GetTokens(ctx, "agent-2")

	if tokens1 != 10.0 {
		t.Errorf("Expected agent-1 tokens=10.0, got %f", tokens1)
	}
	if tokens2 != 3.0 {
		t.Errorf("Expected agent-2 tokens=3.0, got %f", tokens2)
	}
}

// ---------------------------------------------------------------------------
// KeyDBRateLimitStore Tests (using miniredis)
// ---------------------------------------------------------------------------

func newTestKeyDBRateLimitStore(t *testing.T) (*KeyDBRateLimitStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	store := NewKeyDBRateLimitStore(client)
	t.Cleanup(func() { _ = client.Close() })

	return store, mr
}

func TestKeyDBRateLimitStore_GetTokens_NotFound(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	tokens, lastFill, err := store.GetTokens(ctx, "spiffe://test/agent")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if tokens != -1 {
		t.Errorf("Expected tokens=-1 for nonexistent key, got %f", tokens)
	}
	if !lastFill.IsZero() {
		t.Errorf("Expected zero lastFill for nonexistent key, got %v", lastFill)
	}
}

func TestKeyDBRateLimitStore_SetAndGetTokens(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/agent"
	now := time.Now()

	if err := store.SetTokens(ctx, spiffeID, 7.25, now); err != nil {
		t.Fatalf("SetTokens error: %v", err)
	}

	tokens, lastFill, err := store.GetTokens(ctx, spiffeID)
	if err != nil {
		t.Fatalf("GetTokens error: %v", err)
	}
	if tokens != 7.25 {
		t.Errorf("Expected tokens=7.25, got %f", tokens)
	}
	// UnixNano round-trip preserves nanosecond precision
	if lastFill.UnixNano() != now.UnixNano() {
		t.Errorf("Expected lastFill UnixNano=%d, got %d", now.UnixNano(), lastFill.UnixNano())
	}
}

func TestKeyDBRateLimitStore_KeyFormat(t *testing.T) {
	store, mr := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://poc.local/agents/test"
	now := time.Now()

	_ = store.SetTokens(ctx, spiffeID, 5.0, now)

	// Verify the exact key format: ratelimit:{spiffe_id}:tokens
	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	if !mr.Exists(tokensKey) {
		t.Errorf("Expected key %s to exist in KeyDB", tokensKey)
	}
	if !mr.Exists(lastFillKey) {
		t.Errorf("Expected key %s to exist in KeyDB", lastFillKey)
	}

	// Verify value is correct
	tokensVal, err := mr.Get(tokensKey)
	if err != nil {
		t.Fatalf("Failed to get tokens from miniredis: %v", err)
	}
	parsedTokens, _ := strconv.ParseFloat(tokensVal, 64)
	if parsedTokens != 5.0 {
		t.Errorf("Expected tokens=5.0 in KeyDB, got %f", parsedTokens)
	}
}

func TestKeyDBRateLimitStore_TTL(t *testing.T) {
	store, mr := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/ttl-agent"
	now := time.Now()

	_ = store.SetTokens(ctx, spiffeID, 10.0, now)

	// Verify TTL is set (120s)
	tokensKey := rateLimitTokensKey(spiffeID)
	lastFillKey := rateLimitLastFillKey(spiffeID)

	ttlTokens := mr.TTL(tokensKey)
	if ttlTokens <= 0 {
		t.Errorf("Expected positive TTL on tokens key, got %v", ttlTokens)
	}
	if ttlTokens > 120*time.Second {
		t.Errorf("Expected TTL <= 120s, got %v", ttlTokens)
	}

	ttlLastFill := mr.TTL(lastFillKey)
	if ttlLastFill <= 0 {
		t.Errorf("Expected positive TTL on last_fill key, got %v", ttlLastFill)
	}
	if ttlLastFill > 120*time.Second {
		t.Errorf("Expected TTL <= 120s, got %v", ttlLastFill)
	}

	// Fast-forward past TTL to verify auto-expiry
	mr.FastForward(121 * time.Second)

	tokens, _, err := store.GetTokens(ctx, spiffeID)
	if err != nil {
		t.Fatalf("GetTokens after TTL error: %v", err)
	}
	if tokens != -1 {
		t.Errorf("Expected tokens=-1 after TTL expiry, got %f", tokens)
	}
}

func TestKeyDBRateLimitStore_PerAgentIsolation(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	now := time.Now()
	_ = store.SetTokens(ctx, "agent-1", 10.0, now)
	_ = store.SetTokens(ctx, "agent-2", 3.0, now)

	tokens1, _, _ := store.GetTokens(ctx, "agent-1")
	tokens2, _, _ := store.GetTokens(ctx, "agent-2")

	if tokens1 != 10.0 {
		t.Errorf("Expected agent-1 tokens=10.0, got %f", tokens1)
	}
	if tokens2 != 3.0 {
		t.Errorf("Expected agent-2 tokens=3.0, got %f", tokens2)
	}
}

// ---------------------------------------------------------------------------
// RateLimiter Tests (with InMemoryRateLimitStore)
// ---------------------------------------------------------------------------

func TestNewRateLimiter(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(100, 20, store)
	if limiter == nil {
		t.Fatal("expected non-nil rate limiter")
	}
	if limiter.rpm != 100 {
		t.Errorf("expected rpm=100, got %d", limiter.rpm)
	}
	if limiter.burst != 20 {
		t.Errorf("expected burst=20, got %d", limiter.burst)
	}
	if limiter.store == nil {
		t.Error("expected non-nil store")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(60, 10, store) // 1 req/sec with 10 burst

	spiffeID := "spiffe://example.org/agent/test"

	// First request should be allowed
	allowed, remaining, resetTime := limiter.Allow(spiffeID)
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	// After consuming 1 token from initial 10, remaining = 9
	if remaining != 9 {
		t.Errorf("expected remaining=9, got %d", remaining)
	}
	if resetTime.IsZero() {
		t.Error("expected non-zero reset time")
	}

	// Reset time should be in the future
	if !resetTime.After(time.Now()) {
		t.Error("expected reset time to be in the future")
	}
}

func TestRateLimiter_PerAgentBuckets(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(60, 5, store) // 1 req/sec with 5 burst

	agent1 := "spiffe://example.org/agent/1"
	agent2 := "spiffe://example.org/agent/2"

	// Both agents should start with independent buckets
	allowed1, _, _ := limiter.Allow(agent1)
	allowed2, _, _ := limiter.Allow(agent2)

	if !allowed1 {
		t.Error("expected agent1 request to be allowed")
	}
	if !allowed2 {
		t.Error("expected agent2 request to be allowed")
	}
}

func TestRateLimiter_WithKeyDBStore(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(60, 3, store) // 1 req/sec with 3 burst

	spiffeID := "spiffe://poc.local/agents/test"

	// First 3 requests should succeed (burst = 3)
	for i := 0; i < 3; i++ {
		allowed, _, _ := limiter.Allow(spiffeID)
		if !allowed {
			t.Errorf("expected request %d to be allowed", i+1)
		}
	}

	// 4th request should be rate limited
	allowed, _, _ := limiter.Allow(spiffeID)
	if allowed {
		t.Error("expected 4th request to be rate limited")
	}
}

func TestRateLimiter_KeyDBPersistence(t *testing.T) {
	// Verify state persists across RateLimiter instances sharing the same store
	store, _ := newTestKeyDBRateLimitStore(t)

	spiffeID := "spiffe://poc.local/agents/persistent"

	// Instance 1: consume some tokens
	limiter1 := NewRateLimiter(60, 5, store)
	for i := 0; i < 3; i++ {
		allowed, _, _ := limiter1.Allow(spiffeID)
		if !allowed {
			t.Errorf("limiter1: expected request %d to be allowed", i+1)
		}
	}

	// Instance 2: should see the consumed tokens from instance 1
	limiter2 := NewRateLimiter(60, 5, store)
	// We consumed 3 of 5 tokens, so 2 remain. Next 2 should be allowed.
	allowed, _, _ := limiter2.Allow(spiffeID)
	if !allowed {
		t.Error("limiter2: expected 4th request to be allowed (2 tokens remaining)")
	}
	allowed, _, _ = limiter2.Allow(spiffeID)
	if !allowed {
		t.Error("limiter2: expected 5th request to be allowed (1 token remaining)")
	}

	// 6th overall should be rate limited
	allowed, _, _ = limiter2.Allow(spiffeID)
	if allowed {
		t.Error("limiter2: expected 6th request to be rate limited")
	}
}

func TestRateLimiter_KeyDBPerAgentEnforcement(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(1, 1, store) // 1 rpm, burst 1

	agent1 := "spiffe://poc.local/agents/agent1"
	agent2 := "spiffe://poc.local/agents/agent2"

	// Agent1 uses its token
	allowed, _, _ := limiter.Allow(agent1)
	if !allowed {
		t.Error("agent1 first request should be allowed")
	}

	// Agent1 rate limited
	allowed, _, _ = limiter.Allow(agent1)
	if allowed {
		t.Error("agent1 second request should be rate limited")
	}

	// Agent2 has its own bucket, should be allowed
	allowed, _, _ = limiter.Allow(agent2)
	if !allowed {
		t.Error("agent2 should have independent rate limit bucket")
	}
}

func TestRateLimiter_ConcurrentBurstEnforces429_InMemoryStore(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(60, 10, store) // 1 req/sec, burst 10
	spiffeID := "spiffe://example.org/agent/concurrent"

	var denied atomic.Int32
	var wg sync.WaitGroup
	const goroutines = 50

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			allowed, _, _ := limiter.Allow(spiffeID)
			if !allowed {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	// With burst=10 and 50 concurrent requests, we should see some denials.
	if denied.Load() == 0 {
		t.Fatal("expected at least one rate-limited request under concurrent burst, got 0 denials")
	}
}

func TestRateLimiter_ConcurrentBurstEnforces429_KeyDBStore(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(60, 10, store) // 1 req/sec, burst 10
	spiffeID := "spiffe://poc.local/agents/concurrent"

	var denied atomic.Int32
	var wg sync.WaitGroup
	const goroutines = 50

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			allowed, _, _ := limiter.Allow(spiffeID)
			if !allowed {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	// With burst=10 and 50 concurrent requests, we should see some denials.
	if denied.Load() == 0 {
		t.Fatal("expected at least one rate-limited request under concurrent burst, got 0 denials")
	}
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware Tests
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_AllowedRequest(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(100, 20, store)

	// Create handler that should be called
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)

	// Create request with SPIFFE ID in context
	req := httptest.NewRequest("POST", "/mcp", nil)
	req = req.WithContext(WithSPIFFEID(req.Context(), "spiffe://example.org/agent/test"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify request was allowed
	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify rate limit headers are present
	if limit := rec.Header().Get("X-RateLimit-Limit"); limit != "100" {
		t.Errorf("expected X-RateLimit-Limit=100, got %s", limit)
	}
	if remaining := rec.Header().Get("X-RateLimit-Remaining"); remaining == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
	if reset := rec.Header().Get("X-RateLimit-Reset"); reset == "" {
		t.Error("expected X-RateLimit-Reset header")
	}
}

func TestRateLimitMiddleware_MissingSPIFFEID(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(100, 20, store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called without SPIFFE ID")
	})

	handler := RateLimitMiddleware(next, limiter)

	// Create request WITHOUT SPIFFE ID
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should be denied
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestRateLimitMiddleware_RateLimitExceeded(t *testing.T) {
	// Very low rate limit: 1 request per minute with burst of 1
	// Token bucket starts with 1 token, so only first request succeeds immediately
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(1, 1, store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)
	spiffeID := "spiffe://example.org/agent/test"

	// First request should succeed (uses the initial token)
	req1 := httptest.NewRequest("POST", "/mcp", nil)
	req1 = req1.WithContext(WithSPIFFEID(req1.Context(), spiffeID))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected first request to succeed with status 200, got %d", rec1.Code)
	}

	// Immediate second request should be rate limited (no tokens left, refill too slow)
	req2 := httptest.NewRequest("POST", "/mcp", nil)
	req2 = req2.WithContext(WithSPIFFEID(req2.Context(), spiffeID))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec2.Code)
	}

	// Verify rate limit headers are present even in 429 response
	if limit := rec2.Header().Get("X-RateLimit-Limit"); limit != "1" {
		t.Errorf("expected X-RateLimit-Limit=1, got %s", limit)
	}

	// Verify unified JSON error envelope
	var respBody GatewayError
	if err := json.NewDecoder(rec2.Body).Decode(&respBody); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if respBody.Code != ErrRateLimitExceeded {
		t.Errorf("expected code=%q, got %q", ErrRateLimitExceeded, respBody.Code)
	}
	if respBody.Middleware != "rate_limit" {
		t.Errorf("expected middleware=rate_limit, got %q", respBody.Middleware)
	}
	if respBody.MiddlewareStep != 11 {
		t.Errorf("expected middleware_step=11, got %d", respBody.MiddlewareStep)
	}
	if respBody.Details == nil {
		t.Error("expected details in response")
	} else if _, exists := respBody.Details["retry_after_seconds"]; !exists {
		t.Error("expected retry_after_seconds in details")
	}
}

func TestRateLimitMiddleware_IndependentAgentLimits(t *testing.T) {
	// Low rate limit: 1 request per minute with burst of 1
	// Each agent gets 1 initial token
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(1, 1, store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)

	agent1 := "spiffe://example.org/agent/1"
	agent2 := "spiffe://example.org/agent/2"

	// Agent1 makes first request (uses initial token)
	req1a := httptest.NewRequest("POST", "/mcp", nil)
	req1a = req1a.WithContext(WithSPIFFEID(req1a.Context(), agent1))
	rec1a := httptest.NewRecorder()
	handler.ServeHTTP(rec1a, req1a)

	if rec1a.Code != http.StatusOK {
		t.Errorf("expected agent1 first request to succeed, got %d", rec1a.Code)
	}

	// Agent1 immediate second request should be rate limited (token exhausted)
	req1b := httptest.NewRequest("POST", "/mcp", nil)
	req1b = req1b.WithContext(WithSPIFFEID(req1b.Context(), agent1))
	rec1b := httptest.NewRecorder()
	handler.ServeHTTP(rec1b, req1b)

	if rec1b.Code != http.StatusTooManyRequests {
		t.Errorf("expected agent1 second request to be rate limited, got %d", rec1b.Code)
	}

	// Agent2 request should still succeed (independent bucket with fresh token)
	req2 := httptest.NewRequest("POST", "/mcp", nil)
	req2 = req2.WithContext(WithSPIFFEID(req2.Context(), agent2))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected agent2 request to succeed with independent limit, got %d", rec2.Code)
	}
}

func TestRateLimitMiddleware_HeaderGeneration(t *testing.T) {
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(100, 20, store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)

	req := httptest.NewRequest("POST", "/mcp", nil)
	req = req.WithContext(WithSPIFFEID(req.Context(), "spiffe://example.org/agent/test"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify all required headers
	headers := rec.Header()

	limit := headers.Get("X-RateLimit-Limit")
	if limit != "100" {
		t.Errorf("expected X-RateLimit-Limit=100, got %s", limit)
	}

	remaining := headers.Get("X-RateLimit-Remaining")
	if remaining == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
	if remainingInt, err := strconv.Atoi(remaining); err != nil || remainingInt < 0 {
		t.Errorf("expected valid X-RateLimit-Remaining, got %s", remaining)
	}

	reset := headers.Get("X-RateLimit-Reset")
	if reset == "" {
		t.Error("expected X-RateLimit-Reset header")
	}
	if resetInt, err := strconv.ParseInt(reset, 10, 64); err != nil || resetInt <= 0 {
		t.Errorf("expected valid X-RateLimit-Reset unix timestamp, got %s", reset)
	}
}

func TestRateLimitMiddleware_BurstAllowance(t *testing.T) {
	// 60 req/min (1/sec) with burst of 3
	store := NewInMemoryRateLimitStore()
	limiter := NewRateLimiter(60, 3, store)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)
	spiffeID := "spiffe://example.org/agent/test"

	// Burst: first 3 requests should succeed (burst = bucket size)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		req = req.WithContext(WithSPIFFEID(req.Context(), spiffeID))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected request %d to succeed, got %d", i+1, rec.Code)
		}
	}

	// 4th request should be rate limited (burst exhausted, refill too slow)
	req4 := httptest.NewRequest("POST", "/mcp", nil)
	req4 = req4.WithContext(WithSPIFFEID(req4.Context(), spiffeID))
	rec4 := httptest.NewRecorder()
	handler.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusTooManyRequests {
		t.Errorf("expected 4th request to be rate limited, got %d", rec4.Code)
	}
}

// ---------------------------------------------------------------------------
// KeyDB Integration: Middleware with KeyDB Store
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_WithKeyDBStore(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(100, 20, store)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)

	req := httptest.NewRequest("POST", "/mcp", nil)
	req = req.WithContext(WithSPIFFEID(req.Context(), "spiffe://poc.local/agents/keydb-test"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Verify X-RateLimit headers are correct
	if limit := rec.Header().Get("X-RateLimit-Limit"); limit != "100" {
		t.Errorf("expected X-RateLimit-Limit=100, got %s", limit)
	}
	remaining := rec.Header().Get("X-RateLimit-Remaining")
	if remaining == "" {
		t.Error("expected X-RateLimit-Remaining header")
	}
	remainingInt, err := strconv.Atoi(remaining)
	if err != nil {
		t.Fatalf("failed to parse remaining: %v", err)
	}
	// After 1 request from burst of 20, remaining should be 19
	if remainingInt != 19 {
		t.Errorf("expected remaining=19, got %d", remainingInt)
	}
}

func TestRateLimitMiddleware_KeyDB_RateLimitExceeded(t *testing.T) {
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(1, 1, store) // 1 rpm, burst 1

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := RateLimitMiddleware(next, limiter)
	spiffeID := "spiffe://poc.local/agents/limited"

	// First request succeeds
	req1 := httptest.NewRequest("POST", "/mcp", nil)
	req1 = req1.WithContext(WithSPIFFEID(req1.Context(), spiffeID))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected first request to succeed, got %d", rec1.Code)
	}

	// Second request should be 429
	req2 := httptest.NewRequest("POST", "/mcp", nil)
	req2 = req2.WithContext(WithSPIFFEID(req2.Context(), spiffeID))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec2.Code)
	}

	// Verify rate limit headers on 429 response
	if limit := rec2.Header().Get("X-RateLimit-Limit"); limit != "1" {
		t.Errorf("expected X-RateLimit-Limit=1, got %s", limit)
	}
	if remaining := rec2.Header().Get("X-RateLimit-Remaining"); remaining != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", remaining)
	}
}

func TestRateLimitMiddleware_KeyDB_StatePersistsAcrossRequests(t *testing.T) {
	// This integration test proves that rate limit state persists in KeyDB
	// across multiple HTTP requests, enabling distributed rate limiting.
	store, _ := newTestKeyDBRateLimitStore(t)
	limiter := NewRateLimiter(60, 3, store) // burst 3

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	spiffeID := "spiffe://poc.local/agents/persistent-test"

	// Simulate 3 requests across "different gateway instances" by using
	// separate middleware handlers but the same underlying store
	for i := 0; i < 3; i++ {
		handler := RateLimitMiddleware(next, NewRateLimiter(60, 3, store))
		req := httptest.NewRequest("POST", "/mcp", nil)
		req = req.WithContext(WithSPIFFEID(req.Context(), spiffeID))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d should succeed, got %d", i+1, rec.Code)
		}
	}

	// 4th request via yet another "instance" should be rate limited
	handler4 := RateLimitMiddleware(next, limiter)
	req4 := httptest.NewRequest("POST", "/mcp", nil)
	req4 = req4.WithContext(WithSPIFFEID(req4.Context(), spiffeID))
	rec4 := httptest.NewRecorder()
	handler4.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exhausting tokens across instances, got %d", rec4.Code)
	}
}

func TestKeyDBRateLimitStore_AutoExpiry(t *testing.T) {
	// Verify entries auto-expire after 120s TTL (AC #3)
	store, mr := newTestKeyDBRateLimitStore(t)
	ctx := context.Background()

	spiffeID := "spiffe://test/expiry-agent"
	now := time.Now()

	_ = store.SetTokens(ctx, spiffeID, 5.0, now)

	// Verify keys exist
	tokens, _, _ := store.GetTokens(ctx, spiffeID)
	if tokens == -1 {
		t.Fatal("Expected tokens to exist before expiry")
	}

	// Fast-forward past 120s TTL
	mr.FastForward(121 * time.Second)

	// Keys should be gone
	tokens, _, _ = store.GetTokens(ctx, spiffeID)
	if tokens != -1 {
		t.Errorf("Expected tokens=-1 after 120s TTL expiry, got %f", tokens)
	}
}
