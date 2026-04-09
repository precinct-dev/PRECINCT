// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Unit tests: ipRateLimiter
// ---------------------------------------------------------------------------

func TestIPRateLimiter_AllowWithinBurst(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	rl := newIPRateLimiter(1, 5, clock)
	defer rl.Close()

	// 5 requests should be allowed (burst capacity).
	for i := 0; i < 5; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// 6th request should be denied (burst exhausted, no time elapsed).
	if rl.allow("10.0.0.1") {
		t.Fatal("request 6 should be denied after burst exhaustion")
	}
}

func TestIPRateLimiter_RefillAfterTime(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	// Rate of 2/sec, burst of 2.
	rl := newIPRateLimiter(2, 2, clock)
	defer rl.Close()

	// Exhaust burst.
	if !rl.allow("10.0.0.1") {
		t.Fatal("request 1 should be allowed")
	}
	if !rl.allow("10.0.0.1") {
		t.Fatal("request 2 should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("request 3 should be denied")
	}

	// Advance 1 second -- should refill 2 tokens.
	advance(1 * time.Second)

	if !rl.allow("10.0.0.1") {
		t.Fatal("request after refill should be allowed")
	}
	if !rl.allow("10.0.0.1") {
		t.Fatal("second request after refill should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("third request after refill should be denied")
	}
}

func TestIPRateLimiter_IndependentBucketsPerIP(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	rl := newIPRateLimiter(1, 2, clock)
	defer rl.Close()

	// Exhaust IP A.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")
	if rl.allow("10.0.0.1") {
		t.Fatal("IP A should be exhausted")
	}

	// IP B should still be allowed.
	if !rl.allow("10.0.0.2") {
		t.Fatal("IP B should be allowed independently")
	}
}

func TestIPRateLimiter_TokensCappedAtBurst(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	// Rate of 100/sec, burst of 3. Even after waiting a long time,
	// the bucket should cap at 3.
	rl := newIPRateLimiter(100, 3, clock)
	defer rl.Close()

	// Exhaust all tokens.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")

	// Wait 10 seconds -- would accumulate 1000 tokens, but capped at 3.
	advance(10 * time.Second)

	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.allow("10.0.0.1") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("expected exactly 3 allowed (burst cap), got %d", allowed)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: extractClientIP
// ---------------------------------------------------------------------------

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		expected   string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"[::1]:8080", "::1"},
		{"127.0.0.1", "127.0.0.1"}, // no port
	}

	for _, tc := range tests {
		r := &http.Request{RemoteAddr: tc.remoteAddr}
		got := extractClientIP(r)
		if got != tc.expected {
			t.Errorf("extractClientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.expected)
		}
	}
}

func TestExtractTrustedClientIP(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs("10.0.0.0/8,192.168.0.0/16")
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs: %v", err)
	}

	t.Run("untrusted remote ignores forwarded headers", func(t *testing.T) {
		req := &http.Request{
			RemoteAddr: "203.0.113.10:443",
			Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.7"}},
		}
		if got := extractTrustedClientIP(req, trusted); got != "203.0.113.10" {
			t.Fatalf("extractTrustedClientIP() = %q, want %q", got, "203.0.113.10")
		}
	})

	t.Run("trusted proxy returns first non-proxy address", func(t *testing.T) {
		req := &http.Request{
			RemoteAddr: "10.0.0.20:443",
			Header:     http.Header{"X-Forwarded-For": []string{"198.51.100.7, 10.1.1.3"}},
		}
		if got := extractTrustedClientIP(req, trusted); got != "198.51.100.7" {
			t.Fatalf("extractTrustedClientIP() = %q, want %q", got, "198.51.100.7")
		}
	})
}

// ---------------------------------------------------------------------------
// Unit tests: publicEndpointWrapper
// ---------------------------------------------------------------------------

func TestPublicEndpointWrapper_RejectOversizedBody(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 100,
		RateLimit:       100,
		RateBurst:       100,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)

	// Body larger than 100 bytes.
	largeBody := strings.Repeat("x", 200)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", strings.NewReader(largeBody))
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}

	var errResp publicEndpointErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != "request_too_large" {
		t.Errorf("expected error code 'request_too_large', got %q", errResp.Error)
	}
}

func TestPublicEndpointWrapper_AcceptSmallBody(t *testing.T) {
	var receivedBody string
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readBody(r)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 1000,
		RateLimit:       100,
		RateBurst:       100,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)

	payload := `{"credential_type":"api_key","credential":"test123"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange", strings.NewReader(payload))
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()

	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if receivedBody != payload {
		t.Errorf("body not preserved: got %q, want %q", receivedBody, payload)
	}
}

func TestPublicEndpointWrapper_RateLimitTriggersAfterBurst(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 4096,
		RateLimit:       1,
		RateBurst:       3,
		Now:             clock,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)

	// First 3 requests should succeed (burst capacity).
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange",
			strings.NewReader(`{"credential_type":"api_key","credential":"test"}`))
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		wrapped.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rr.Code)
		}
	}

	// 4th request should be rate limited.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange",
		strings.NewReader(`{"credential_type":"api_key","credential":"test"}`))
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}

	var errResp publicEndpointErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Error != "ratelimit_exceeded" {
		t.Errorf("expected error code 'ratelimit_exceeded', got %q", errResp.Error)
	}

	// Verify Retry-After header is present.
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestPublicEndpointWrapper_DifferentIPsIndependent(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 4096,
		RateLimit:       1,
		RateBurst:       1,
		Now:             clock,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)

	// Exhaust IP A.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange",
		strings.NewReader(`{}`))
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("IP A first request should succeed, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange",
		strings.NewReader(`{}`))
	req2.RemoteAddr = "10.0.0.1:1234"
	rr2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A second request should be rate limited, got %d", rr2.Code)
	}

	// IP B should still work.
	req3 := httptest.NewRequest(http.MethodPost, "/v1/auth/token-exchange",
		strings.NewReader(`{}`))
	req3.RemoteAddr = "10.0.0.2:5678"
	rr3 := httptest.NewRecorder()
	wrapped.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("IP B should succeed independently, got %d", rr3.Code)
	}
}

func TestPublicEndpointWrapper_NilBodyPassesThrough(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 100,
		RateLimit:       100,
		RateBurst:       100,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)

	// GET request with no body -- should pass through size check.
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/token-exchange", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for nil body, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: audit logging
// ---------------------------------------------------------------------------

func TestPublicEndpointWrapper_AuditEntryFormat(t *testing.T) {
	// Verify the audit entry struct marshals correctly with all required fields.
	entry := publicEndpointAuditEntry{
		Timestamp:  "2026-03-17T10:00:00.000Z",
		RemoteIP:   "192.168.1.1",
		DecisionID: "abc123",
		TraceID:    "def456",
		Path:       "/v1/auth/token-exchange",
		Method:     "POST",
		Result:     "denied",
		Detail:     "rate_limited",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal audit entry: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal audit entry: %v", err)
	}

	required := []string{"timestamp", "remote_ip", "decision_id", "trace_id", "path", "method", "result"}
	for _, field := range required {
		if _, ok := parsed[field]; !ok {
			t.Errorf("audit entry missing required field %q", field)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration tests: full HTTP server, no mocks
// ---------------------------------------------------------------------------

func TestIntegration_PublicEndpoint_RateLimitTriggersAfterN(t *testing.T) {
	// Stand up a real HTTP server with the public endpoint wrapper.
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 4096,
		RateLimit:       1,
		RateBurst:       5, // Allow exactly 5, then deny.
	}
	wrapped := publicEndpointWrapper(innerHandler, cfg)
	server := httptest.NewServer(wrapped)
	defer server.Close()

	client := server.Client()
	allowed := 0
	denied := 0
	totalRequests := 10

	for i := 0; i < totalRequests; i++ {
		body := bytes.NewReader([]byte(`{"credential_type":"api_key","credential":"test"}`))
		resp, err := client.Post(server.URL+"/v1/auth/token-exchange", "application/json", body)
		if err != nil {
			t.Fatalf("request %d failed: %v", i+1, err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			denied++
			// Verify the response body is a valid JSON error.
			var errResp publicEndpointErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
				t.Fatalf("request %d: failed to decode 429 response: %v", i+1, err)
			}
			if errResp.Error != "ratelimit_exceeded" {
				t.Errorf("request %d: expected error code 'ratelimit_exceeded', got %q", i+1, errResp.Error)
			}
		default:
			t.Errorf("request %d: unexpected status %d", i+1, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	if allowed != 5 {
		t.Errorf("expected exactly 5 allowed requests (burst), got %d", allowed)
	}
	if denied != 5 {
		t.Errorf("expected exactly 5 denied requests, got %d", denied)
	}
}

func TestIntegration_PublicEndpoint_MalformedBodyRejected(t *testing.T) {
	// Inner handler: the real token exchange handler expects valid JSON.
	// But the size limit should reject before we even get there.
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the body -- if it's malformed JSON, this will fail.
		var req TokenExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(publicEndpointErrorResponse{
				Error:   "invalid_body",
				Message: "Invalid JSON request body",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 4096,
		RateLimit:       100,
		RateBurst:       100,
	}
	wrapped := publicEndpointWrapper(innerHandler, cfg)
	server := httptest.NewServer(wrapped)
	defer server.Close()

	client := server.Client()

	// Test 1: Oversized body rejected with 413.
	largeBody := bytes.NewReader([]byte(strings.Repeat("x", 5000)))
	resp, err := client.Post(server.URL+"/v1/auth/token-exchange", "application/json", largeBody)
	if err != nil {
		t.Fatalf("oversized request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: expected 413, got %d", resp.StatusCode)
	}

	// Test 2: Malformed JSON passes size check but rejected by inner handler.
	malformed := bytes.NewReader([]byte(`{not valid json`))
	resp2, err := client.Post(server.URL+"/v1/auth/token-exchange", "application/json", malformed)
	if err != nil {
		t.Fatalf("malformed request failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed body: expected 400, got %d", resp2.StatusCode)
	}
}

func TestIntegration_PublicEndpoint_ExactSizeBoundary(t *testing.T) {
	// Test the exact boundary: body of exactly MaxRequestBytes should be allowed,
	// but MaxRequestBytes+1 should be rejected.
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := PublicEndpointConfig{
		MaxRequestBytes: 50,
		RateLimit:       100,
		RateBurst:       100,
	}
	wrapped := publicEndpointWrapper(okHandler, cfg)
	server := httptest.NewServer(wrapped)
	defer server.Close()

	client := server.Client()

	// Exactly 50 bytes -- should be allowed.
	exactBody := bytes.NewReader([]byte(strings.Repeat("a", 50)))
	resp, err := client.Post(server.URL+"/test", "application/json", exactBody)
	if err != nil {
		t.Fatalf("exact-size request failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exact-size body (50 bytes): expected 200, got %d", resp.StatusCode)
	}

	// 51 bytes -- should be rejected.
	overBody := bytes.NewReader([]byte(strings.Repeat("a", 51)))
	resp2, err := client.Post(server.URL+"/test", "application/json", overBody)
	if err != nil {
		t.Fatalf("over-size request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-size body (51 bytes): expected 413, got %d", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Unit tests: ipRateLimiter TTL eviction
// ---------------------------------------------------------------------------

func TestIPRateLimiter_EvictsStaleEntries(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	ttl := 5 * time.Minute
	rl := newIPRateLimiterWithTTL(1, 5, ttl, clock)
	defer rl.Close()

	// Create entries for two IPs.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")

	if c := rl.bucketCount(); c != 2 {
		t.Fatalf("expected 2 buckets before eviction, got %d", c)
	}

	// Advance past TTL.
	advance(6 * time.Minute)

	// Manually trigger eviction (do not rely on ticker timing in tests).
	rl.evictExpired()

	if c := rl.bucketCount(); c != 0 {
		t.Fatalf("expected 0 buckets after TTL eviction, got %d", c)
	}
}

func TestIPRateLimiter_ActiveEntriesPreserved(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	ttl := 5 * time.Minute
	rl := newIPRateLimiterWithTTL(1, 5, ttl, clock)
	defer rl.Close()

	// Create entries for two IPs.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")

	// Advance 4 minutes (under TTL).
	advance(4 * time.Minute)

	// Touch only IP 1 (renewing its access time).
	rl.allow("10.0.0.1")

	// Advance another 2 minutes (total 6 min since IP 2 last access,
	// but only 2 min since IP 1 last access).
	advance(2 * time.Minute)

	rl.evictExpired()

	// IP 2 should be evicted (6 min idle), IP 1 should be preserved (2 min idle).
	if c := rl.bucketCount(); c != 1 {
		t.Fatalf("expected 1 bucket after selective eviction, got %d", c)
	}

	// IP 1 should still be functional.
	if !rl.allow("10.0.0.1") {
		t.Fatal("IP 1 should still be allowed after eviction of IP 2")
	}
}

func TestIPRateLimiter_EvictionIsConcurrentSafe(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	ttl := 5 * time.Minute
	rl := newIPRateLimiterWithTTL(10, 20, ttl, clock)
	defer rl.Close()

	// Populate many entries concurrently while eviction runs.
	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent writers.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.0.%d.%d", id/256, id%256)
			for j := 0; j < 10; j++ {
				rl.allow(ip)
			}
		}(i)
	}

	// Concurrent eviction.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			rl.evictExpired()
		}
	}()

	wg.Wait()
	// Test passes if no data races are detected (run with -race).
}

func TestIPRateLimiter_CloseIsIdempotent(t *testing.T) {
	rl := newIPRateLimiter(1, 5, nil)
	// Calling Close multiple times should not panic.
	rl.Close()
	rl.Close()
	rl.Close()
}

func TestIPRateLimiter_BucketRecreatedAfterEviction(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	ttl := 5 * time.Minute
	// Rate = 1/sec, burst = 2.
	rl := newIPRateLimiterWithTTL(1, 2, ttl, clock)
	defer rl.Close()

	// Exhaust burst for IP.
	rl.allow("10.0.0.1")
	rl.allow("10.0.0.1")
	if rl.allow("10.0.0.1") {
		t.Fatal("should be denied after burst exhaustion")
	}

	// Advance past TTL and evict.
	advance(6 * time.Minute)
	rl.evictExpired()

	if c := rl.bucketCount(); c != 0 {
		t.Fatalf("expected 0 buckets after eviction, got %d", c)
	}

	// New request from same IP should get a fresh bucket with full burst.
	if !rl.allow("10.0.0.1") {
		t.Fatal("should be allowed after eviction recreated the bucket")
	}
	if !rl.allow("10.0.0.1") {
		t.Fatal("second request should be allowed (fresh burst=2)")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("third request should be denied (burst exhausted)")
	}
}

func TestIPRateLimiter_CustomTTL(t *testing.T) {
	now := time.Now()
	mu := sync.Mutex{}
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	// Custom 30-second TTL.
	ttl := 30 * time.Second
	rl := newIPRateLimiterWithTTL(1, 5, ttl, clock)
	defer rl.Close()

	rl.allow("10.0.0.1")

	// 25 seconds: still within TTL.
	advance(25 * time.Second)
	rl.evictExpired()
	if c := rl.bucketCount(); c != 1 {
		t.Fatalf("expected 1 bucket at 25s (within 30s TTL), got %d", c)
	}

	// 31 seconds total: past TTL.
	advance(6 * time.Second)
	rl.evictExpired()
	if c := rl.bucketCount(); c != 0 {
		t.Fatalf("expected 0 buckets at 31s (past 30s TTL), got %d", c)
	}
}

func TestIPRateLimiter_DefaultBucketTTL(t *testing.T) {
	if defaultBucketTTL != 5*time.Minute {
		t.Fatalf("expected defaultBucketTTL = 5m, got %v", defaultBucketTTL)
	}
}

// readBody is a test helper to read the request body.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}
