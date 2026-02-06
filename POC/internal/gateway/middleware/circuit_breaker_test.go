package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- CircuitState string representation ---

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state    CircuitState
		expected string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.expected {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

// --- NewCircuitBreaker defaults ---

func TestNewCircuitBreaker_Defaults(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{}, nil)

	if cb.failureThreshold != 5 {
		t.Errorf("expected default failureThreshold=5, got %d", cb.failureThreshold)
	}
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("expected default resetTimeout=30s, got %v", cb.resetTimeout)
	}
	if cb.successThreshold != 2 {
		t.Errorf("expected default successThreshold=2, got %d", cb.successThreshold)
	}
	if cb.state != CircuitClosed {
		t.Errorf("expected initial state=Closed, got %v", cb.state)
	}
}

func TestNewCircuitBreaker_CustomConfig(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 10,
		ResetTimeout:     60 * time.Second,
		SuccessThreshold: 3,
	}
	cb := NewCircuitBreaker(cfg, nil)

	if cb.failureThreshold != 10 {
		t.Errorf("expected failureThreshold=10, got %d", cb.failureThreshold)
	}
	if cb.resetTimeout != 60*time.Second {
		t.Errorf("expected resetTimeout=60s, got %v", cb.resetTimeout)
	}
	if cb.successThreshold != 3 {
		t.Errorf("expected successThreshold=3, got %d", cb.successThreshold)
	}
}

func TestNewCircuitBreaker_InvalidConfigUsesDefaults(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: -1,
		ResetTimeout:     -1,
		SuccessThreshold: 0,
	}
	cb := NewCircuitBreaker(cfg, nil)

	if cb.failureThreshold != 5 {
		t.Errorf("expected default failureThreshold=5 for invalid input, got %d", cb.failureThreshold)
	}
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("expected default resetTimeout=30s for invalid input, got %v", cb.resetTimeout)
	}
	if cb.successThreshold != 2 {
		t.Errorf("expected default successThreshold=2 for invalid input, got %d", cb.successThreshold)
	}
}

// --- State Machine Transitions ---

func TestCircuitBreaker_ClosedToOpen(t *testing.T) {
	var transitions []string
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     30 * time.Second,
		SuccessThreshold: 2,
	}, func(from, to CircuitState) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})

	// Record failures below threshold - should stay closed
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Errorf("expected Closed after 2 failures, got %v", cb.State())
	}

	// 3rd failure should trip the circuit
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after 3 failures, got %v", cb.State())
	}

	// Verify transition was recorded
	if len(transitions) != 1 || transitions[0] != "closed->open" {
		t.Errorf("expected [closed->open] transition, got %v", transitions)
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     30 * time.Second,
		SuccessThreshold: 2,
	}, nil)

	// 2 failures then 1 success
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()

	// 2 more failures should NOT trip (counter was reset by success)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Errorf("expected Closed after reset+2 failures, got %v", cb.State())
	}

	// 3rd consecutive failure (from reset) trips it
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after 3 consecutive failures, got %v", cb.State())
	}
}

func TestCircuitBreaker_OpenToHalfOpen(t *testing.T) {
	now := time.Now()
	var transitions []string

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 1,
	}, func(from, to CircuitState) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})
	cb.now = func() time.Time { return now }

	// Trip the circuit
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected Open, got %v", cb.State())
	}

	// Before timeout, should stay open
	cb.now = func() time.Time { return now.Add(5 * time.Second) }
	if cb.State() != CircuitOpen {
		t.Errorf("expected Open before timeout, got %v", cb.State())
	}

	// After timeout, State() should transition to Half-Open
	cb.now = func() time.Time { return now.Add(10 * time.Second) }
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected HalfOpen after timeout, got %v", cb.State())
	}

	// Verify transitions: closed->open, open->half-open
	if len(transitions) != 2 {
		t.Errorf("expected 2 transitions, got %d: %v", len(transitions), transitions)
	}
}

func TestCircuitBreaker_HalfOpenToClosedOnSuccess(t *testing.T) {
	now := time.Now()
	var transitions []string

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 2,
	}, func(from, to CircuitState) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})
	cb.now = func() time.Time { return now }

	// Trip circuit
	cb.RecordFailure()

	// Move past timeout to half-open
	cb.now = func() time.Time { return now.Add(11 * time.Second) }
	_ = cb.State() // triggers transition

	// First success in half-open
	cb.RecordSuccess()
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected HalfOpen after 1 success (threshold=2), got %v", cb.State())
	}

	// Second success should close the circuit
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("expected Closed after 2 successes, got %v", cb.State())
	}

	// Verify full transition chain
	expected := []string{"closed->open", "open->half-open", "half-open->closed"}
	if len(transitions) != len(expected) {
		t.Fatalf("expected %d transitions, got %d: %v", len(expected), len(transitions), transitions)
	}
	for i, want := range expected {
		if transitions[i] != want {
			t.Errorf("transition[%d] = %q, want %q", i, transitions[i], want)
		}
	}
}

func TestCircuitBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	now := time.Now()
	var transitions []string

	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 2,
	}, func(from, to CircuitState) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})
	cb.now = func() time.Time { return now }

	// Trip circuit
	cb.RecordFailure()

	// Move past timeout to half-open
	cb.now = func() time.Time { return now.Add(11 * time.Second) }
	_ = cb.State()

	// Failure in half-open should reopen
	cb.RecordFailure()

	// After reopening, we need to move time forward again to not auto-transition
	reopenedAt := now.Add(11 * time.Second)
	cb.now = func() time.Time { return reopenedAt.Add(1 * time.Second) }
	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after half-open failure, got %v", cb.State())
	}

	// Verify transitions: closed->open, open->half-open, half-open->open
	expected := []string{"closed->open", "open->half-open", "half-open->open"}
	if len(transitions) != len(expected) {
		t.Fatalf("expected %d transitions, got %d: %v", len(expected), len(transitions), transitions)
	}
	for i, want := range expected {
		if transitions[i] != want {
			t.Errorf("transition[%d] = %q, want %q", i, transitions[i], want)
		}
	}
}

// --- AllowRequest ---

func TestCircuitBreaker_AllowRequest_Closed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{}, nil)

	if !cb.AllowRequest() {
		t.Error("expected request allowed in Closed state")
	}
}

func TestCircuitBreaker_AllowRequest_Open(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     30 * time.Second,
	}, nil)
	cb.now = func() time.Time { return now }

	cb.RecordFailure() // trip circuit

	// Requests should be blocked in Open state
	cb.now = func() time.Time { return now.Add(1 * time.Second) }
	if cb.AllowRequest() {
		t.Error("expected request blocked in Open state")
	}
}

func TestCircuitBreaker_AllowRequest_OpenAfterTimeout(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
	}, nil)
	cb.now = func() time.Time { return now }

	cb.RecordFailure() // trip circuit

	// After timeout, AllowRequest should transition to half-open and allow
	cb.now = func() time.Time { return now.Add(10 * time.Second) }
	if !cb.AllowRequest() {
		t.Error("expected request allowed after reset timeout (half-open)")
	}
}

func TestCircuitBreaker_AllowRequest_HalfOpen(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
	}, nil)
	cb.now = func() time.Time { return now }

	cb.RecordFailure()

	// Transition to half-open
	cb.now = func() time.Time { return now.Add(10 * time.Second) }
	_ = cb.State()

	// Requests should be allowed in Half-Open state
	if !cb.AllowRequest() {
		t.Error("expected request allowed in HalfOpen state")
	}
}

// --- RetryAfterSeconds ---

func TestCircuitBreaker_RetryAfterSeconds_Closed(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{}, nil)

	if retryAfter := cb.RetryAfterSeconds(); retryAfter != 0 {
		t.Errorf("expected RetryAfterSeconds=0 in Closed state, got %d", retryAfter)
	}
}

func TestCircuitBreaker_RetryAfterSeconds_Open(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     30 * time.Second,
	}, nil)
	cb.now = func() time.Time { return now }

	cb.RecordFailure() // trip circuit

	// Check retry after immediately
	cb.now = func() time.Time { return now.Add(5 * time.Second) }
	retryAfter := cb.RetryAfterSeconds()
	if retryAfter < 24 || retryAfter > 25 {
		t.Errorf("expected RetryAfterSeconds ~25, got %d", retryAfter)
	}
}

// --- Middleware Tests ---

func TestCircuitBreakerMiddleware_ClosedState_PassesThrough(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 5,
	}, nil)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := CircuitBreakerMiddleware(next, cb)

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("expected next handler to be called in Closed state")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestCircuitBreakerMiddleware_OpenState_Returns503(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     30 * time.Second,
	}, nil)
	cb.now = func() time.Time { return now }

	// Trip the circuit
	cb.RecordFailure()

	// Keep time shortly after trip so circuit stays open
	cb.now = func() time.Time { return now.Add(1 * time.Second) }

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	handler := CircuitBreakerMiddleware(next, cb)

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify 503 returned
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}

	// Verify next handler was NOT called
	if nextCalled {
		t.Error("expected next handler NOT to be called when circuit is open")
	}

	// Verify JSON response body
	var respBody map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&respBody); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if respBody["error"] != "circuit_breaker_open" {
		t.Errorf("expected error=circuit_breaker_open, got %v", respBody["error"])
	}
	if respBody["message"] != "upstream temporarily unavailable" {
		t.Errorf("expected message='upstream temporarily unavailable', got %v", respBody["message"])
	}
	if _, exists := respBody["retry_after_seconds"]; !exists {
		t.Error("expected retry_after_seconds in response")
	}

	// Verify Retry-After header
	if retryAfter := rec.Header().Get("Retry-After"); retryAfter == "" {
		t.Error("expected Retry-After header")
	}

	// Verify Content-Type header
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %s", ct)
	}
}

func TestCircuitBreakerMiddleware_Records5xxAsFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     30 * time.Second,
	}, nil)

	// Handler that returns 500
	failingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := CircuitBreakerMiddleware(failingHandler, cb)

	// Make 3 requests that return 500
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("request %d: expected status 500, got %d", i+1, rec.Code)
		}
	}

	// Circuit should now be open
	if cb.State() != CircuitOpen {
		t.Errorf("expected circuit to be Open after 3 5xx responses, got %v", cb.State())
	}

	// 4th request should get 503 (circuit open)
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 when circuit open, got %d", rec.Code)
	}
}

func TestCircuitBreakerMiddleware_Records2xxAsSuccess(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		ResetTimeout:     30 * time.Second,
	}, nil)

	// Handler that alternates failures and successes
	// 2 failures, then 1 success (should reset counter), then 2 more failures
	responses := []int{500, 500, 200, 500, 500}
	callIndex := 0

	variableHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callIndex < len(responses) {
			w.WriteHeader(responses[callIndex])
			callIndex++
		}
	})

	handler := CircuitBreakerMiddleware(variableHandler, cb)

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// After 2 failures, 1 success (reset), 2 failures: should still be Closed
	// (consecutive failures = 2, threshold = 3)
	if cb.State() != CircuitClosed {
		t.Errorf("expected circuit Closed (success reset failure count), got %v", cb.State())
	}
}

func TestCircuitBreakerMiddleware_HalfOpenRecovery(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 2,
	}, nil)
	cb.now = func() time.Time { return now }

	// Trip circuit with a failure
	failingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	handler := CircuitBreakerMiddleware(failingHandler, cb)
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Move past timeout
	cb.now = func() time.Time { return now.Add(11 * time.Second) }

	// Now create a successful handler for recovery
	successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler = CircuitBreakerMiddleware(successHandler, cb)

	// First success in half-open
	req = httptest.NewRequest("POST", "/mcp", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 in half-open, got %d", rec.Code)
	}
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected HalfOpen after 1 success (threshold=2), got %v", cb.State())
	}

	// Second success should close the circuit
	req = httptest.NewRequest("POST", "/mcp", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if cb.State() != CircuitClosed {
		t.Errorf("expected Closed after 2 successes, got %v", cb.State())
	}
}

func TestCircuitBreakerMiddleware_HalfOpenFailureReopens(t *testing.T) {
	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 2,
	}, nil)
	cb.now = func() time.Time { return now }

	// Trip circuit
	cb.RecordFailure()

	// Move to half-open
	cb.now = func() time.Time { return now.Add(11 * time.Second) }
	_ = cb.State()

	// Failure in half-open via middleware
	failingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	handler := CircuitBreakerMiddleware(failingHandler, cb)

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Circuit should be back to Open
	// Move time to just after the half-open failure so it does NOT immediately re-enter half-open
	halfOpenFailedAt := now.Add(11 * time.Second)
	cb.now = func() time.Time { return halfOpenFailedAt.Add(1 * time.Second) }
	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after half-open failure, got %v", cb.State())
	}
}

func TestCircuitBreakerMiddleware_Various5xxCodes(t *testing.T) {
	codes := []int{500, 501, 502, 503, 504}

	for _, code := range codes {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			FailureThreshold: 1,
		}, nil)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		})

		handler := CircuitBreakerMiddleware(next, cb)
		req := httptest.NewRequest("POST", "/mcp", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if cb.State() != CircuitOpen {
			t.Errorf("status %d: expected circuit Open after failure, got %v", code, cb.State())
		}
	}
}

func TestCircuitBreakerMiddleware_4xxNotCountedAsFailure(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1,
	}, nil)

	// 4xx responses should NOT trip the circuit
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest) // 400
	})

	handler := CircuitBreakerMiddleware(next, cb)
	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if cb.State() != CircuitClosed {
		t.Errorf("expected circuit Closed after 4xx response, got %v", cb.State())
	}
}

// --- Concurrency Safety ---

func TestCircuitBreaker_ConcurrencySafety(t *testing.T) {
	baseTime := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 100,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 10,
	}, nil)
	// Use setNow (thread-safe) to inject a deterministic clock.
	// This prevents a data race on the cb.now field when concurrent
	// goroutines read it under the mutex while the test sets it.
	cb.setNow(func() time.Time { return baseTime })

	var wg sync.WaitGroup
	iterations := 500

	// Phase 1: Concurrent failures must trip the circuit.
	// All goroutines call RecordFailure() under the mutex, so ordering
	// is serialized. With 500 failures and threshold=100, the circuit
	// will deterministically reach Open state.
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func() {
			defer wg.Done()
			cb.RecordFailure()
		}()
	}
	wg.Wait()

	if cb.State() != CircuitOpen {
		t.Errorf("expected Open after %d concurrent failures (threshold=100), got %v", iterations, cb.State())
	}

	// Phase 2: Transition from Open to Half-Open via clock advancement.
	// setNow is thread-safe -- no goroutines are running at this point,
	// but we use it consistently to avoid any latent race on the field.
	cb.setNow(func() time.Time { return baseTime.Add(11 * time.Second) })
	_ = cb.State() // triggers Open -> HalfOpen transition

	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected HalfOpen after timeout, got %v", cb.State())
	}

	// Phase 3: Sequential successes to recover from Half-Open to Closed.
	// Concurrent successes in Half-Open are intentionally avoided because
	// a single failure would reopen the circuit -- that behavior is tested
	// elsewhere. Here we verify the recovery path.
	for i := 0; i < 10; i++ {
		cb.RecordSuccess()
	}

	if cb.State() != CircuitClosed {
		t.Errorf("expected Closed after %d sequential successes (threshold=10), got %v", 10, cb.State())
	}

	// Phase 4: Concurrent reads must not panic or corrupt state.
	// The circuit is Closed, so State()/AllowRequest() should not trigger
	// any transitions. We verify no panics under concurrent access.
	cb.setNow(func() time.Time { return baseTime.Add(20 * time.Second) })
	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		go func() {
			defer wg.Done()
			_ = cb.State()
			_ = cb.AllowRequest()
			_ = cb.RetryAfterSeconds()
		}()
	}
	wg.Wait()

	// Phase 5: Concurrent mixed reads and writes must not panic.
	// Half the goroutines record failures, half read state. This tests
	// that the mutex correctly serializes all access paths.
	cb.setNow(func() time.Time { return baseTime.Add(30 * time.Second) })
	// Reset to closed state for this phase
	cb2 := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 100,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 10,
	}, nil)
	cb2.setNow(func() time.Time { return baseTime.Add(30 * time.Second) })

	wg.Add(iterations)
	for i := 0; i < iterations; i++ {
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				cb2.RecordFailure()
			}()
		} else {
			go func() {
				defer wg.Done()
				_ = cb2.State()
				_ = cb2.AllowRequest()
			}()
		}
	}
	wg.Wait()

	// After 250 concurrent failures (threshold=100), circuit must be open
	if cb2.State() != CircuitOpen {
		t.Errorf("expected Open after concurrent mixed reads/writes, got %v", cb2.State())
	}
}

// --- State Transition Audit Callback ---

func TestCircuitBreaker_StateTransitionCallback(t *testing.T) {
	var mu sync.Mutex
	var transitions []struct {
		from, to CircuitState
	}

	now := time.Now()
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 2,
		ResetTimeout:     10 * time.Second,
		SuccessThreshold: 1,
	}, func(from, to CircuitState) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, struct{ from, to CircuitState }{from, to})
	})
	cb.now = func() time.Time { return now }

	// Trip circuit
	cb.RecordFailure()
	cb.RecordFailure()

	// Move to half-open
	cb.now = func() time.Time { return now.Add(11 * time.Second) }
	_ = cb.State()

	// Recover
	cb.RecordSuccess()

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 3 {
		t.Fatalf("expected 3 transitions, got %d: %v", len(transitions), transitions)
	}

	// Verify: closed->open, open->half-open, half-open->closed
	expected := []struct{ from, to CircuitState }{
		{CircuitClosed, CircuitOpen},
		{CircuitOpen, CircuitHalfOpen},
		{CircuitHalfOpen, CircuitClosed},
	}
	for i, exp := range expected {
		if transitions[i].from != exp.from || transitions[i].to != exp.to {
			t.Errorf("transition[%d]: expected %v->%v, got %v->%v",
				i, exp.from, exp.to, transitions[i].from, transitions[i].to)
		}
	}
}

// --- circuitBreakerResponseWriter ---

func TestCircuitBreakerResponseWriter_CapturesStatusCode(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &circuitBreakerResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	w.WriteHeader(http.StatusBadGateway)

	if w.statusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", w.statusCode)
	}
}

func TestCircuitBreakerResponseWriter_DefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &circuitBreakerResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Write without explicit WriteHeader
	_, _ = w.Write([]byte("hello"))

	if w.statusCode != http.StatusOK {
		t.Errorf("expected default status 200, got %d", w.statusCode)
	}
}

func TestCircuitBreakerResponseWriter_OnlyFirstWriteHeaderCounts(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &circuitBreakerResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	w.WriteHeader(http.StatusBadGateway)
	w.WriteHeader(http.StatusOK) // second call should not overwrite

	if w.statusCode != http.StatusBadGateway {
		t.Errorf("expected first status 502 to be preserved, got %d", w.statusCode)
	}
}
