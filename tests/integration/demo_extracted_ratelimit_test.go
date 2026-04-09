// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

// Demo-extracted rate limit integration tests.
// Extracts the deterministic rate limit assertion from demo/go/main.go into
// httptest-based integration tests using the real in-memory rate limiter.
//
// Covers demo assertion:
// - Rate limit burst (429 on rapid calls) -- testRateLimit

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// buildRateLimitChain constructs a middleware chain with real rate limiter,
// SPIFFE auth, and body capture. The rate limiter uses an in-memory store
// with configurable RPM and burst values for deterministic testing.
func buildRateLimitChain(rpm, burst int) http.Handler {
	store := middleware.NewInMemoryRateLimitStore()
	limiter := middleware.NewRateLimiter(rpm, burst, store)

	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"reached_terminal"}`))
	})

	// Build chain: BodyCapture -> SPIFFEAuth -> RateLimit -> terminal
	handler := middleware.RateLimitMiddleware(terminal, limiter)
	handler = middleware.SPIFFEAuth(handler, "dev")
	handler = middleware.BodyCapture(handler)

	return handler
}

// rateLimitRequest builds a minimal JSON-RPC request for rate limit testing.
func rateLimitRequest() string {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "tavily_search",
			"arguments": map[string]any{"query": "test"},
		},
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// ---------------------------------------------------------------------------
// Demo assertion: Rate limit burst (429 on rapid calls)
// ---------------------------------------------------------------------------

// TestDemoExtracted_RateLimit_BurstExhaustion mirrors demo test
// "Rate limit burst (429 on rapid calls)".
// Uses a very low burst (3) so we can deterministically exhaust the bucket
// in a test without needing thousands of requests.
func TestDemoExtracted_RateLimit_BurstExhaustion(t *testing.T) {
	// Low RPM and burst for deterministic testing. Burst=3 means
	// the 4th request should be rate-limited.
	handler := buildRateLimitChain(60, 3)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	body := rateLimitRequest()

	// Send burst+1 requests. The first `burst` should succeed; the next should get 429.
	var saw429 bool
	var lastStatus int
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", spiffeID)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		lastStatus = rr.Code

		if rr.Code == http.StatusTooManyRequests {
			saw429 = true

			// Verify the 429 response structure matches what the demo expects.
			var ge middleware.GatewayError
			if err := json.Unmarshal(rr.Body.Bytes(), &ge); err != nil {
				t.Fatalf("Failed to parse 429 error body: %v", err)
			}
			if ge.Code != middleware.ErrRateLimitExceeded {
				t.Errorf("Expected code=%s, got %s", middleware.ErrRateLimitExceeded, ge.Code)
			}
			if ge.MiddlewareStep != 11 {
				t.Errorf("Expected middleware_step=11, got %d", ge.MiddlewareStep)
			}

			// Verify rate limit headers are present (demo checks these).
			if rr.Header().Get("X-RateLimit-Limit") == "" {
				t.Error("Missing X-RateLimit-Limit header on 429 response")
			}
			if rr.Header().Get("X-RateLimit-Remaining") == "" {
				t.Error("Missing X-RateLimit-Remaining header on 429 response")
			}
			if rr.Header().Get("X-RateLimit-Reset") == "" {
				t.Error("Missing X-RateLimit-Reset header on 429 response")
			}

			t.Logf("PASS: Rate limit hit at request %d (429) with code=%s", i+1, ge.Code)
			break
		}
	}

	if !saw429 {
		t.Fatalf("Expected 429 after burst exhaustion, last status was %d", lastStatus)
	}
}

// ---------------------------------------------------------------------------
// Rate limit headers present on normal responses
// ---------------------------------------------------------------------------

// TestDemoExtracted_RateLimit_HeadersPresent verifies that rate limit headers
// are present even on successful (non-429) responses. This is part of the
// demo's verification that per-identity throttling is active.
func TestDemoExtracted_RateLimit_HeadersPresent(t *testing.T) {
	handler := buildRateLimitChain(100, 20) // generous limit, won't hit 429
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	body := rateLimitRequest()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if limit := rr.Header().Get("X-RateLimit-Limit"); limit == "" {
		t.Error("Missing X-RateLimit-Limit header")
	} else {
		t.Logf("X-RateLimit-Limit: %s", limit)
	}
	if remaining := rr.Header().Get("X-RateLimit-Remaining"); remaining == "" {
		t.Error("Missing X-RateLimit-Remaining header")
	} else {
		t.Logf("X-RateLimit-Remaining: %s", remaining)
	}
	if reset := rr.Header().Get("X-RateLimit-Reset"); reset == "" {
		t.Error("Missing X-RateLimit-Reset header")
	} else {
		t.Logf("X-RateLimit-Reset: %s", reset)
	}

	t.Logf("PASS: Rate limit headers present on successful response (HTTP %d)", rr.Code)
}

// ---------------------------------------------------------------------------
// Independent per-agent rate limits
// ---------------------------------------------------------------------------

// TestDemoExtracted_RateLimit_IndependentPerAgent verifies that different
// SPIFFE IDs have independent rate limit buckets. Exhausting one agent's
// bucket should not affect another agent.
func TestDemoExtracted_RateLimit_IndependentPerAgent(t *testing.T) {
	handler := buildRateLimitChain(60, 2) // burst=2 for quick exhaustion
	body := rateLimitRequest()

	agentA := "spiffe://poc.local/agents/mcp-client/agent-a/dev"
	agentB := "spiffe://poc.local/agents/mcp-client/agent-b/dev"

	// Exhaust agent A's bucket.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", agentA)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	// Agent B should still have tokens available.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", agentB)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusTooManyRequests {
		t.Fatalf("Agent B should not be rate-limited (independent bucket), got 429")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 for agent B, got %d", rr.Code)
	}
	t.Logf("PASS: Agent B has independent rate limit bucket (HTTP %d)", rr.Code)
}
