// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// OC-uli2: Public endpoint hardening -- rate limit, request size limit, and
// audit logging for unauthenticated public endpoints (e.g., token exchange).
//
// These endpoints sit outside the main middleware chain, so they need
// compensating controls against brute-force and abuse.
package gateway

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PublicEndpointConfig holds tunable parameters for public endpoint protection.
type PublicEndpointConfig struct {
	// MaxRequestBytes is the maximum allowed request body size.
	// Requests larger than this are rejected with HTTP 413 before any
	// expensive processing (e.g., bcrypt verification).
	MaxRequestBytes int64

	// RateLimit is the sustained request rate per IP per second.
	RateLimit float64

	// RateBurst is the maximum burst size (token bucket capacity).
	RateBurst int

	// BucketTTL is how long an idle IP rate-limit entry is kept before
	// eviction. Zero means use the default (5 minutes).
	BucketTTL time.Duration

	// Now is an injectable clock for testing. Defaults to time.Now.
	Now func() time.Time

	// ClientIPResolver extracts the caller IP for rate limiting and audit.
	// Defaults to the direct remote address when unset.
	ClientIPResolver func(*http.Request) string
}

// DefaultPublicEndpointConfig returns sensible defaults for public endpoint
// protection. 10 requests/second sustained with a burst of 20 covers
// legitimate automated callers while throttling brute-force.
func DefaultPublicEndpointConfig() PublicEndpointConfig {
	return PublicEndpointConfig{
		MaxRequestBytes: 4096,
		RateLimit:       10,
		RateBurst:       20,
	}
}

// publicEndpointAuditEntry is the structured audit entry written for every
// public endpoint request that reaches the wrapper (both denied and allowed).
type publicEndpointAuditEntry struct {
	Timestamp  string `json:"timestamp"`
	RemoteIP   string `json:"remote_ip"`
	DecisionID string `json:"decision_id"`
	TraceID    string `json:"trace_id"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	Result     string `json:"result"`
	Detail     string `json:"detail,omitempty"`
}

// defaultBucketTTL is the default time-to-live for idle IP rate limiter
// entries. Entries not accessed within this window are evicted by a
// background goroutine, bounding memory proportionally to the rate of
// unique IPs within the window.
const defaultBucketTTL = 5 * time.Minute

// ipRateLimiter is a simple in-memory token bucket rate limiter keyed by IP.
// It uses sync.Map for lock-free reads on the fast path, with per-bucket
// mutexes to prevent races during token consumption. A background goroutine
// periodically evicts entries that have not been accessed within the
// configured TTL to prevent unbounded memory growth.
type ipRateLimiter struct {
	buckets     sync.Map // map[string]*tokenBucket
	lastAccess  sync.Map // map[string]time.Time
	rate        float64  // tokens per second
	burst       int      // maximum bucket capacity
	ttl         time.Duration
	now         func() time.Time
	stopCleanup chan struct{}
}

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
}

func newIPRateLimiter(rate float64, burst int, now func() time.Time) *ipRateLimiter {
	return newIPRateLimiterWithTTL(rate, burst, defaultBucketTTL, now)
}

// newIPRateLimiterWithTTL creates a rate limiter with a configurable eviction
// TTL. A background goroutine runs at ttl/2 intervals to evict stale entries.
// Call Close() to stop the goroutine.
func newIPRateLimiterWithTTL(rate float64, burst int, ttl time.Duration, now func() time.Time) *ipRateLimiter {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = defaultBucketTTL
	}
	rl := &ipRateLimiter{
		rate:        rate,
		burst:       burst,
		ttl:         ttl,
		now:         now,
		stopCleanup: make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Close stops the background eviction goroutine. Safe to call multiple times.
func (rl *ipRateLimiter) Close() {
	select {
	case <-rl.stopCleanup:
		// Already closed.
	default:
		close(rl.stopCleanup)
	}
}

func (rl *ipRateLimiter) cleanupLoop() {
	interval := rl.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evictExpired()
		case <-rl.stopCleanup:
			return
		}
	}
}

func (rl *ipRateLimiter) evictExpired() {
	now := rl.now()
	rl.lastAccess.Range(func(key, value any) bool {
		ip := key.(string)
		accessed := value.(time.Time)
		if now.Sub(accessed) > rl.ttl {
			rl.buckets.Delete(ip)
			rl.lastAccess.Delete(ip)
		}
		return true
	})
}

// allow checks whether the given IP is within rate limits. Returns true if
// the request is allowed (a token was consumed), false if rate limited.
// This is fail-closed: if anything goes wrong, it denies.
func (rl *ipRateLimiter) allow(ip string) bool {
	now := rl.now()

	// Record access time for TTL eviction.
	rl.lastAccess.Store(ip, now)

	val, _ := rl.buckets.LoadOrStore(ip, &tokenBucket{
		tokens:   float64(rl.burst),
		lastFill: now,
	})
	bucket := val.(*tokenBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(bucket.lastFill).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * rl.rate
		if bucket.tokens > float64(rl.burst) {
			bucket.tokens = float64(rl.burst)
		}
		bucket.lastFill = now
	}

	// Try to consume one token.
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

// bucketCount returns the number of tracked IP entries. Intended for testing.
func (rl *ipRateLimiter) bucketCount() int {
	count := 0
	rl.buckets.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// publicEndpointWrapper wraps an HTTP handler with public endpoint protections:
//  1. Request size limit (reject > MaxRequestBytes with 413)
//  2. IP-based rate limiting (reject with 429 when over limit)
//  3. Audit logging for all outcomes (denied and allowed)
//
// The wrapper generates a decision_id and trace_id for each request since
// these endpoints sit outside the main middleware chain that normally
// assigns those identifiers.
func publicEndpointWrapper(next http.Handler, cfg PublicEndpointConfig) http.Handler {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	clientIPResolver := cfg.ClientIPResolver
	if clientIPResolver == nil {
		clientIPResolver = extractClientIP
	}

	ttl := cfg.BucketTTL
	if ttl <= 0 {
		ttl = defaultBucketTTL
	}
	limiter := newIPRateLimiterWithTTL(cfg.RateLimit, cfg.RateBurst, ttl, nowFn)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP := clientIPResolver(r)
		decisionID := generateHexID()
		traceID := generateHexID()

		auditLog := func(result, detail string) {
			entry := publicEndpointAuditEntry{
				Timestamp:  nowFn().UTC().Format(time.RFC3339Nano),
				RemoteIP:   remoteIP,
				DecisionID: decisionID,
				TraceID:    traceID,
				Path:       r.URL.Path,
				Method:     r.Method,
				Result:     result,
				Detail:     detail,
			}
			data, err := json.Marshal(entry)
			if err != nil {
				slog.Error("public endpoint audit marshal error", "error", err)
				return
			}
			slog.Info("public_endpoint_audit", "entry", string(data))
		}

		// Step 1: Request size limit.
		if r.Body != nil && r.ContentLength != 0 {
			limited := io.LimitReader(r.Body, cfg.MaxRequestBytes+1)
			bodyBytes, err := io.ReadAll(limited)
			_ = r.Body.Close()

			if err != nil {
				auditLog("denied", "body_read_error")
				writePublicEndpointError(w, http.StatusBadRequest,
					"request_body_error", "Failed to read request body")
				return
			}

			if int64(len(bodyBytes)) > cfg.MaxRequestBytes {
				auditLog("denied", "request_too_large")
				writePublicEndpointError(w, http.StatusRequestEntityTooLarge,
					"request_too_large", "Request body exceeds maximum allowed size")
				return
			}

			// Restore the body for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		// Step 2: IP-based rate limit.
		if !limiter.allow(remoteIP) {
			auditLog("denied", "rate_limited")
			w.Header().Set("Retry-After", "1")
			writePublicEndpointError(w, http.StatusTooManyRequests,
				"ratelimit_exceeded", "Rate limit exceeded for this IP")
			return
		}

		// Step 3: Allowed -- audit and pass through.
		auditLog("allowed", "")
		next.ServeHTTP(w, r)
	})
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	cidrs := strings.Split(raw, ",")
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, network)
	}
	return trusted, nil
}

func ipFromRemoteAddr(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(strings.TrimSpace(remoteAddr))
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP returns the direct client IP from the request remote address.
func extractClientIP(r *http.Request) string {
	if ip := ipFromRemoteAddr(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// extractTrustedClientIP returns the first non-proxy IP from X-Forwarded-For
// only when the direct peer is in the trusted proxy CIDR set.
func extractTrustedClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIP := ipFromRemoteAddr(r.RemoteAddr)
	if remoteIP == nil || !ipInNetworks(remoteIP, trustedProxies) {
		return extractClientIP(r)
	}

	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor == "" {
		return extractClientIP(r)
	}

	parts := strings.Split(forwardedFor, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(parts[i]))
		if candidate == nil {
			continue
		}
		if !ipInNetworks(candidate, trustedProxies) {
			return candidate.String()
		}
	}

	return extractClientIP(r)
}

// generateHexID produces a 16-byte (32 hex char) cryptographic random ID.
func generateHexID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a timestamp-based ID if crypto/rand fails.
		// This should essentially never happen.
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}

// publicEndpointErrorResponse is the JSON error envelope for public endpoint
// rejections. Kept deliberately minimal -- callers do not have SPIFFE
// identities yet, so we expose less detail than the main middleware chain.
type publicEndpointErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writePublicEndpointError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(publicEndpointErrorResponse{
		Error:   errorCode,
		Message: message,
	})
}
