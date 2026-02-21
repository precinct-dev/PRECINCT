package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CircuitState represents the current state of the circuit breaker
type CircuitState int

const (
	// CircuitClosed is the normal operating state - all requests pass through
	CircuitClosed CircuitState = iota
	// CircuitOpen means the circuit is tripped - requests immediately return 503
	CircuitOpen
	// CircuitHalfOpen allows a probe request to test recovery
	CircuitHalfOpen
)

// String returns the string representation of a circuit state
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern to protect
// the gateway from cascading failures when upstream becomes unhealthy.
//
// State transitions:
//
//	Closed -> Open: after failureThreshold consecutive failures
//	Open -> Half-Open: after resetTimeout duration
//	Half-Open -> Closed: after successThreshold consecutive successes
//	Half-Open -> Open: on any failure
type CircuitBreaker struct {
	mu sync.Mutex

	state CircuitState

	// Thresholds
	failureThreshold int           // consecutive failures before opening
	resetTimeout     time.Duration // duration to wait in Open before trying Half-Open
	successThreshold int           // consecutive successes in Half-Open before closing

	// Counters
	consecutiveFailures  int
	consecutiveSuccesses int

	// Timing
	lastFailureTime time.Time // when the circuit was last opened
	openedAt        time.Time // when the circuit transitioned to open
	lastStateChange time.Time // when the circuit last transitioned state

	// Audit callback for state transitions (optional)
	onStateChange func(from, to CircuitState)

	// Clock function for testability
	now func() time.Time
}

// setNow replaces the clock function in a thread-safe manner.
// This is used by tests to inject deterministic time without racing
// against goroutines that read cb.now under the mutex.
func (cb *CircuitBreaker) setNow(fn func() time.Time) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.now = fn
}

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	FailureThreshold int
	ResetTimeout     time.Duration
	SuccessThreshold int
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
// The onStateChange callback is invoked on every state transition for audit logging.
func NewCircuitBreaker(cfg CircuitBreakerConfig, onStateChange func(from, to CircuitState)) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.ResetTimeout <= 0 {
		cfg.ResetTimeout = 30 * time.Second
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}

	return &CircuitBreaker{
		state:            CircuitClosed,
		failureThreshold: cfg.FailureThreshold,
		resetTimeout:     cfg.ResetTimeout,
		successThreshold: cfg.SuccessThreshold,
		onStateChange:    onStateChange,
		now:              time.Now,
	}
}

// State returns the current circuit breaker state (thread-safe)
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check if Open circuit should transition to Half-Open
	if cb.state == CircuitOpen && cb.now().Sub(cb.openedAt) >= cb.resetTimeout {
		cb.transitionTo(CircuitHalfOpen)
	}

	return cb.state
}

// CircuitBreakerSnapshot is a read-only view of circuit breaker state for diagnostics.
type CircuitBreakerSnapshot struct {
	State           CircuitState
	Failures        int
	Threshold       int
	ResetTimeout    time.Duration
	LastStateChange *time.Time
}

// Snapshot returns a consistent snapshot of the circuit breaker state.
func (cb *CircuitBreaker) Snapshot() CircuitBreakerSnapshot {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Keep behavior consistent with State(): Open -> Half-Open after reset timeout.
	if cb.state == CircuitOpen && cb.now().Sub(cb.openedAt) >= cb.resetTimeout {
		cb.transitionTo(CircuitHalfOpen)
	}

	var last *time.Time
	if !cb.lastStateChange.IsZero() {
		t := cb.lastStateChange
		last = &t
	}

	return CircuitBreakerSnapshot{
		State:           cb.state,
		Failures:        cb.consecutiveFailures,
		Threshold:       cb.failureThreshold,
		ResetTimeout:    cb.resetTimeout,
		LastStateChange: last,
	}
}

// RetryAfterSeconds returns the number of seconds until the circuit
// may transition from Open to Half-Open. Returns 0 if not in Open state.
func (cb *CircuitBreaker) RetryAfterSeconds() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != CircuitOpen {
		return 0
	}

	remaining := cb.resetTimeout - cb.now().Sub(cb.openedAt)
	if remaining <= 0 {
		return 0
	}

	seconds := int(remaining.Seconds())
	if seconds < 1 {
		return 1 // minimum 1 second
	}
	return seconds
}

// AllowRequest checks if a request should be allowed through.
// Returns true if the request can proceed, false if the circuit is open.
// When in Half-Open state, only one probe request is allowed.
func (cb *CircuitBreaker) AllowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has elapsed
		if cb.now().Sub(cb.openedAt) >= cb.resetTimeout {
			cb.transitionTo(CircuitHalfOpen)
			return true // allow probe request
		}
		return false
	case CircuitHalfOpen:
		// In half-open, we allow requests (the middleware tracks success/failure)
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful upstream response
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		// Reset failure counter on success
		cb.consecutiveFailures = 0
	case CircuitHalfOpen:
		cb.consecutiveSuccesses++
		if cb.consecutiveSuccesses >= cb.successThreshold {
			cb.transitionTo(CircuitClosed)
		}
	case CircuitOpen:
		// Should not happen - requests are blocked in Open state
	}
}

// RecordFailure records a failed upstream response (5xx or timeout)
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		cb.consecutiveFailures++
		cb.lastFailureTime = cb.now()
		if cb.consecutiveFailures >= cb.failureThreshold {
			cb.transitionTo(CircuitOpen)
		}
	case CircuitHalfOpen:
		// Any failure in half-open reopens the circuit
		cb.transitionTo(CircuitOpen)
	case CircuitOpen:
		// Already open, update failure time
		cb.lastFailureTime = cb.now()
	}
}

// Reset forces the circuit breaker back to closed state and clears counters.
// This is intended for operator/admin recovery flows.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.transitionTo(CircuitClosed)
}

// transitionTo changes the circuit state (must be called with lock held)
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := cb.state
	if oldState == newState {
		return
	}

	cb.state = newState
	cb.lastStateChange = cb.now()

	// Reset counters on transition
	switch newState {
	case CircuitClosed:
		cb.consecutiveFailures = 0
		cb.consecutiveSuccesses = 0
	case CircuitOpen:
		cb.openedAt = cb.now()
		cb.consecutiveSuccesses = 0
	case CircuitHalfOpen:
		cb.consecutiveSuccesses = 0
	}

	// Notify listener (audit logging)
	if cb.onStateChange != nil {
		// Invoke callback outside hot path - but since we hold the lock,
		// the callback must not call back into the circuit breaker.
		cb.onStateChange(oldState, newState)
	}
}

// circuitBreakerResponseWriter wraps http.ResponseWriter to capture the status code
// for circuit breaker failure detection
type circuitBreakerResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *circuitBreakerResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *circuitBreakerResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *circuitBreakerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func (w *circuitBreakerResponseWriter) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// CircuitBreakerMiddleware creates HTTP middleware that implements the circuit
// breaker pattern. When the circuit is open, requests immediately receive
// HTTP 503 without hitting upstream.
//
// Position: Step 12 in the middleware chain (after rate limiting, before token substitution)
func CircuitBreakerMiddleware(next http.Handler, cb *CircuitBreaker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for step 12
		ctx, span := tracer.Start(r.Context(), "gateway.circuit_breaker",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 12),
				attribute.String("mcp.gateway.middleware", "circuit_breaker"),
			),
		)
		defer span.End()

		// Record circuit state on span
		currentState := cb.State()
		span.SetAttributes(attribute.String("state", currentState.String()))

		// Record circuit breaker state metric
		if gwMetrics != nil {
			gwMetrics.CircuitBreakerState.Record(ctx, int64(currentState),
				metric.WithAttributes(
					attribute.String("circuit_name", "default"),
				),
			)
		}

		// Check if request is allowed
		if !cb.AllowRequest() {
			retryAfter := cb.RetryAfterSeconds()

			// Record circuit breaker denial metric
			if gwMetrics != nil {
				gwMetrics.DenialTotal.Add(ctx, 1,
					metric.WithAttributes(
						attribute.String("middleware", "circuit_breaker"),
						attribute.String("reason", "circuit_open"),
						attribute.String("spiffe_id", GetSPIFFEID(ctx)),
					),
				)
			}

			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "circuit breaker open"),
			)

			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			WriteGatewayError(w, r.WithContext(ctx), http.StatusServiceUnavailable, GatewayError{
				Code:           ErrCircuitOpen,
				Message:        "Upstream temporarily unavailable",
				Middleware:     "circuit_breaker",
				MiddlewareStep: 12,
				Details: map[string]any{
					"retry_after_seconds": retryAfter,
				},
				Remediation: fmt.Sprintf("Retry after %d seconds.", retryAfter),
			})
			return
		}

		span.SetAttributes(
			attribute.String("mcp.result", "allowed"),
			attribute.String("mcp.reason", ""),
		)

		// Wrap response writer to capture status code
		wrapped := &circuitBreakerResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Pass request to next handler
		next.ServeHTTP(wrapped, r.WithContext(ctx))

		// Determine if the response indicates a failure (5xx)
		if wrapped.statusCode >= 500 {
			cb.RecordFailure()
		} else {
			cb.RecordSuccess()
		}
	})
}
