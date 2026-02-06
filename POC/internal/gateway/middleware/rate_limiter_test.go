package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(100, 20)
	if limiter == nil {
		t.Fatal("expected non-nil rate limiter")
	}
	if limiter.rpm != 100 {
		t.Errorf("expected rpm=100, got %d", limiter.rpm)
	}
	if limiter.burst != 20 {
		t.Errorf("expected burst=20, got %d", limiter.burst)
	}
	if limiter.limiters == nil {
		t.Error("expected non-nil limiters map")
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	limiter := NewRateLimiter(60, 10) // 1 req/sec with 10 burst

	spiffeID := "spiffe://example.org/agent/test"

	// First request should be allowed
	allowed, remaining, resetTime := limiter.Allow(spiffeID)
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	if remaining != 10 {
		t.Errorf("expected remaining=10, got %d", remaining)
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
	limiter := NewRateLimiter(60, 5) // 1 req/sec with 5 burst

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

	// Verify they have separate limiters
	limiter.mu.RLock()
	if _, exists := limiter.limiters[agent1]; !exists {
		t.Error("expected agent1 limiter to exist")
	}
	if _, exists := limiter.limiters[agent2]; !exists {
		t.Error("expected agent2 limiter to exist")
	}
	limiter.mu.RUnlock()
}

func TestRateLimitMiddleware_AllowedRequest(t *testing.T) {
	limiter := NewRateLimiter(100, 20)

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
	limiter := NewRateLimiter(100, 20)

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
	limiter := NewRateLimiter(1, 1)

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

	// Verify JSON response body
	var respBody map[string]interface{}
	if err := json.NewDecoder(rec2.Body).Decode(&respBody); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if respBody["error"] != "rate_limit_exceeded" {
		t.Errorf("expected error=rate_limit_exceeded, got %v", respBody["error"])
	}

	if _, exists := respBody["retry_after_seconds"]; !exists {
		t.Error("expected retry_after_seconds in response")
	}
}

func TestRateLimitMiddleware_IndependentAgentLimits(t *testing.T) {
	// Low rate limit: 1 request per minute with burst of 1
	// Each agent gets 1 initial token
	limiter := NewRateLimiter(1, 1)

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
	limiter := NewRateLimiter(100, 20)

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
	// The burst value is the bucket size, so we can make burst+initial requests before rate limiting
	limiter := NewRateLimiter(60, 3)

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
