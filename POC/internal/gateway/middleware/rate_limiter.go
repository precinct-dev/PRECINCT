package middleware

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages per-agent rate limits using token bucket algorithm
type RateLimiter struct {
	mu       sync.RWMutex
	limiters map[string]*agentLimiter // keyed by SPIFFE ID
	rpm      int                      // requests per minute
	burst    int                      // burst allowance
}

// agentLimiter tracks rate limit state for a single agent
type agentLimiter struct {
	limiter   *rate.Limiter
	resetTime time.Time
}

// NewRateLimiter creates a new rate limiter with the given RPM and burst
func NewRateLimiter(rpm, burst int) *RateLimiter {
	// Ensure burst is at least 1 to allow initial requests
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		limiters: make(map[string]*agentLimiter),
		rpm:      rpm,
		burst:    burst,
	}
}

// getLimiter retrieves or creates a rate limiter for the given SPIFFE ID
func (rl *RateLimiter) getLimiter(spiffeID string) *agentLimiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if limiter exists
	if limiter, exists := rl.limiters[spiffeID]; exists {
		return limiter
	}

	// Create new limiter with token bucket
	// rate.Limit is tokens per second
	// We want RPM, so divide by 60
	perSecond := float64(rl.rpm) / 60.0

	// The burst is the bucket size - allows burst requests up to this limit
	// rate.NewLimiter(r, b) creates a limiter with rate r tokens/sec and bucket size b
	limiter := &agentLimiter{
		limiter:   rate.NewLimiter(rate.Limit(perSecond), rl.burst),
		resetTime: time.Now().Add(time.Minute),
	}
	rl.limiters[spiffeID] = limiter
	return limiter
}

// Allow checks if a request is allowed under rate limits
func (rl *RateLimiter) Allow(spiffeID string) (allowed bool, remaining int, resetTime time.Time) {
	limiter := rl.getLimiter(spiffeID)

	// Update reset time (rolls forward every minute)
	if time.Now().After(limiter.resetTime) {
		limiter.resetTime = time.Now().Add(time.Minute)
	}

	// Check if request is allowed
	allowed = limiter.limiter.Allow()

	// Calculate remaining tokens (approximate)
	// Note: rate.Limiter doesn't expose tokens directly, so we approximate
	// For more accurate counting, we'd need to track requests ourselves
	remaining = rl.burst // simplified - in real impl, track actual remaining

	return allowed, remaining, limiter.resetTime
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
		limiter: NewRateLimiter(rpm, burst),
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
		ctx := r.Context()

		// Get SPIFFE ID from context (set by SPIFFE auth middleware)
		spiffeID := GetSPIFFEID(ctx)
		if spiffeID == "" {
			// No SPIFFE ID - should not happen if SPIFFE auth passed
			// Fail closed: deny request
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

		// Add rate limit headers to response (in ALL cases, per AC #6)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limiter.rpm))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		// If rate limit exceeded, return HTTP 429
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)

			resp := map[string]interface{}{
				"error":               "rate_limit_exceeded",
				"retry_after_seconds": retryAfter,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Request allowed - continue
		next.ServeHTTP(w, r)
	})
}
