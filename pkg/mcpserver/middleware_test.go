package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Unit Tests: compose / buildPipeline ---

func TestCompose_OrderIsOuterThenInner(t *testing.T) {
	var order []string

	outer := func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			order = append(order, "outer-before")
			result, err := next(ctx, args)
			order = append(order, "outer-after")
			return result, err
		}
	}
	inner := func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			order = append(order, "inner-before")
			result, err := next(ctx, args)
			order = append(order, "inner-after")
			return result, err
		}
	}

	composed := compose(outer, inner)
	handler := composed(func(_ context.Context, _ map[string]any) (any, error) {
		order = append(order, "handler")
		return "ok", nil
	})

	result, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %v, want %q", result, "ok")
	}

	expected := []string{"outer-before", "inner-before", "handler", "inner-after", "outer-after"}
	if len(order) != len(expected) {
		t.Fatalf("order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("order[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestBuildPipeline_Empty(t *testing.T) {
	pipeline := buildPipeline(nil)
	handler := pipeline(func(_ context.Context, _ map[string]any) (any, error) {
		return "passthrough", nil
	})
	result, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "passthrough" {
		t.Errorf("result = %v, want %q", result, "passthrough")
	}
}

func TestBuildPipeline_Ordering(t *testing.T) {
	var order []string
	makeMW := func(name string) Middleware {
		return func(next ToolHandler) ToolHandler {
			return func(ctx context.Context, args map[string]any) (any, error) {
				order = append(order, name)
				return next(ctx, args)
			}
		}
	}

	pipeline := buildPipeline([]Middleware{
		makeMW("first"),
		makeMW("second"),
		makeMW("third"),
	})
	handler := pipeline(func(_ context.Context, _ map[string]any) (any, error) {
		order = append(order, "handler")
		return nil, nil
	})

	if _, err := handler(context.Background(), nil); err != nil {
		t.Fatalf("unexpected pipeline error: %v", err)
	}

	expected := []string{"first", "second", "third", "handler"}
	if len(order) != len(expected) {
		t.Fatalf("order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("order[%d] = %q, want %q", i, order[i], v)
		}
	}
}

// --- Unit Tests: Rate Limiting ---

func TestRateLimitMiddleware_AllowsWithinBurst(t *testing.T) {
	mw := newRateLimitMiddleware(1000, 5)
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	// 5 calls within burst should all succeed.
	for i := range 5 {
		result, err := handler(context.Background(), nil)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if result != "ok" {
			t.Errorf("call %d: result = %v", i, result)
		}
	}
}

func TestRateLimitMiddleware_RejectsAfterBurstExhaustion(t *testing.T) {
	// Very low rate, burst of 2 -- exhaust burst immediately.
	mw := newRateLimitMiddleware(0.001, 2)
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	// Exhaust burst.
	for range 2 {
		if _, err := handler(context.Background(), nil); err != nil {
			t.Fatalf("unexpected rate-limit warmup error: %v", err)
		}
	}

	// Third call should be rejected.
	_, err := handler(context.Background(), nil)
	if err == nil {
		t.Fatal("expected rate limit error, got nil")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "rate limit exceeded")
	}
}

func TestRateLimitMiddleware_PropagatesHandlerError(t *testing.T) {
	mw := newRateLimitMiddleware(100, 10)
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("handler error")
	})

	_, err := handler(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "handler error" {
		t.Errorf("error = %q, want %q", err.Error(), "handler error")
	}
}

// --- Unit Tests: Cache ---

func TestCacheMiddleware_CachesSuccessfulResults(t *testing.T) {
	var callCount int
	mw := newCacheMiddleware(5 * time.Minute)

	// Inject tool name into context (as the context middleware would).
	ctx := withToolCallContext(context.Background(), "test-tool", "session-1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		callCount++
		return "result", nil
	})

	args := map[string]any{"key": "value"}

	// First call: cache miss.
	r1, err := handler(ctx, args)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if r1 != "result" {
		t.Errorf("first call result = %v", r1)
	}
	if callCount != 1 {
		t.Errorf("call count after first = %d, want 1", callCount)
	}

	// Second call: cache hit.
	r2, err := handler(ctx, args)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if r2 != "result" {
		t.Errorf("second call result = %v", r2)
	}
	if callCount != 1 {
		t.Errorf("call count after second = %d, want 1 (cached)", callCount)
	}
}

func TestCacheMiddleware_DoesNotCacheErrors(t *testing.T) {
	var callCount int
	mw := newCacheMiddleware(5 * time.Minute)
	ctx := withToolCallContext(context.Background(), "fail-tool", "session-1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		callCount++
		return nil, fmt.Errorf("error-%d", callCount)
	})

	args := map[string]any{"a": "b"}

	_, err1 := handler(ctx, args)
	if err1 == nil {
		t.Fatal("expected error on first call")
	}

	_, err2 := handler(ctx, args)
	if err2 == nil {
		t.Fatal("expected error on second call")
	}

	// Handler should have been called twice (errors are not cached).
	if callCount != 2 {
		t.Errorf("call count = %d, want 2", callCount)
	}
}

func TestCacheMiddleware_DifferentArgsGetDifferentEntries(t *testing.T) {
	var callCount int
	mw := newCacheMiddleware(5 * time.Minute)
	ctx := withToolCallContext(context.Background(), "multi-tool", "session-1")

	handler := mw(func(_ context.Context, args map[string]any) (any, error) {
		callCount++
		return fmt.Sprintf("result-%v", args["x"]), nil
	})

	r1, _ := handler(ctx, map[string]any{"x": "1"})
	r2, _ := handler(ctx, map[string]any{"x": "2"})
	r3, _ := handler(ctx, map[string]any{"x": "1"}) // cache hit

	if callCount != 2 {
		t.Errorf("call count = %d, want 2", callCount)
	}
	if r1 != "result-1" {
		t.Errorf("r1 = %v", r1)
	}
	if r2 != "result-2" {
		t.Errorf("r2 = %v", r2)
	}
	if r3 != "result-1" {
		t.Errorf("r3 = %v, want cached result-1", r3)
	}
}

func TestCacheMiddleware_ExpiredEntriesAreMisses(t *testing.T) {
	var callCount int
	// Use a very short TTL for testing.
	mw := newCacheMiddleware(1 * time.Millisecond)
	ctx := withToolCallContext(context.Background(), "ttl-tool", "session-1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		callCount++
		return "result", nil
	})

	if _, err := handler(ctx, nil); err != nil {
		t.Fatalf("unexpected cache miss error: %v", err)
	}
	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)
	if _, err := handler(ctx, nil); err != nil {
		t.Fatalf("unexpected cache refresh error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("call count = %d, want 2 (expired entry should be a miss)", callCount)
	}
}

func TestCacheKey_Deterministic(t *testing.T) {
	args := map[string]any{"b": 2, "a": 1}
	k1 := cacheKey("tool", args)
	k2 := cacheKey("tool", args)
	if k1 != k2 {
		t.Errorf("cache key not deterministic: %q vs %q", k1, k2)
	}
}

func TestCacheKey_DifferentToolsDiffer(t *testing.T) {
	args := map[string]any{"a": 1}
	k1 := cacheKey("tool1", args)
	k2 := cacheKey("tool2", args)
	if k1 == k2 {
		t.Error("different tools should produce different cache keys")
	}
}

// --- Unit Tests: Context Injection ---

func TestContextMiddleware_InjectsServerName(t *testing.T) {
	mw := newContextMiddleware("my-server")

	var gotName string
	handler := mw(func(ctx context.Context, _ map[string]any) (any, error) {
		gotName = ServerNameFromContext(ctx)
		return nil, nil
	})

	if _, err := handler(context.Background(), nil); err != nil {
		t.Fatalf("unexpected context middleware error: %v", err)
	}
	if gotName != "my-server" {
		t.Errorf("ServerName = %q, want %q", gotName, "my-server")
	}
}

func TestWithToolCallContext_InjectsToolAndSession(t *testing.T) {
	ctx := withToolCallContext(context.Background(), "my-tool", "session-abc")
	if ToolNameFromContext(ctx) != "my-tool" {
		t.Errorf("ToolName = %q, want %q", ToolNameFromContext(ctx), "my-tool")
	}
	if SessionIDFromContext(ctx) != "session-abc" {
		t.Errorf("SessionID = %q, want %q", SessionIDFromContext(ctx), "session-abc")
	}
}

func TestContextAccessors_EmptyOnPlainContext(t *testing.T) {
	ctx := context.Background()
	if v := ServerNameFromContext(ctx); v != "" {
		t.Errorf("ServerName = %q, want empty", v)
	}
	if v := ToolNameFromContext(ctx); v != "" {
		t.Errorf("ToolName = %q, want empty", v)
	}
	if v := SessionIDFromContext(ctx); v != "" {
		t.Errorf("SessionID = %q, want empty", v)
	}
}

// --- Unit Tests: Logging ---

func TestLoggingMiddleware_LogsSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := newLoggingMiddleware(logger)
	ctx := withToolCallContext(context.Background(), "log-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	if _, err := handler(ctx, map[string]any{"secret": "password123"}); err != nil {
		t.Fatalf("unexpected logging middleware error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "tool call completed") {
		t.Errorf("missing log message in output: %s", output)
	}
	if !strings.Contains(output, `"outcome":"success"`) {
		t.Errorf("missing outcome=success in output: %s", output)
	}
	if !strings.Contains(output, `"tool":"log-tool"`) {
		t.Errorf("missing tool name in output: %s", output)
	}
	if !strings.Contains(output, "duration") {
		t.Errorf("missing duration in output: %s", output)
	}
	// Verify arg values are redacted.
	if strings.Contains(output, "password123") {
		t.Errorf("arg value not redacted in output: %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("missing [REDACTED] in output: %s", output)
	}
}

func TestLoggingMiddleware_LogsError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mw := newLoggingMiddleware(logger)
	ctx := withToolCallContext(context.Background(), "fail-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("broken")
	})

	if _, err := handler(ctx, nil); err == nil {
		t.Fatal("expected handler error")
	}

	output := buf.String()
	if !strings.Contains(output, "tool call failed") {
		t.Errorf("missing error log message: %s", output)
	}
	if !strings.Contains(output, `"outcome":"error"`) {
		t.Errorf("missing outcome=error: %s", output)
	}
	if !strings.Contains(output, "broken") {
		t.Errorf("missing error text: %s", output)
	}
}

func TestRedactArgs(t *testing.T) {
	result := redactArgs(map[string]any{
		"password": "secret",
		"username": "admin",
	})
	if result["password"] != "[REDACTED]" {
		t.Errorf("password = %q", result["password"])
	}
	if result["username"] != "[REDACTED]" {
		t.Errorf("username = %q", result["username"])
	}
}

func TestRedactArgs_Empty(t *testing.T) {
	result := redactArgs(nil)
	if result != nil {
		t.Errorf("expected nil for empty args, got %v", result)
	}
}

// --- Unit Tests: Role Visibility ---

func TestRoleVisibilityMiddleware_AllowsWhenNoRole(t *testing.T) {
	mw := newRoleVisibilityMiddleware(func(ctx context.Context, toolName string) bool {
		return false // deny everything
	})

	ctx := withToolCallContext(context.Background(), "tool", "s1")
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	result, err := handler(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error without role, got: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %v", result)
	}
}

func TestRoleVisibilityMiddleware_DeniesWhenFilterReturnsFalse(t *testing.T) {
	mw := newRoleVisibilityMiddleware(func(ctx context.Context, toolName string) bool {
		return false
	})

	ctx := withToolCallContext(context.Background(), "secret-tool", "s1")
	ctx = WithRole(ctx, "viewer")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	_, err := handler(ctx, nil)
	if err == nil {
		t.Fatal("expected error when role is denied")
	}
	if !strings.Contains(err.Error(), "not visible") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestRoleVisibilityMiddleware_AllowsWhenFilterReturnsTrue(t *testing.T) {
	mw := newRoleVisibilityMiddleware(func(ctx context.Context, toolName string) bool {
		return Role(ctx) == "admin"
	})

	ctx := withToolCallContext(context.Background(), "admin-tool", "s1")
	ctx = WithRole(ctx, "admin")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "admin-result", nil
	})

	result, err := handler(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "admin-result" {
		t.Errorf("result = %v", result)
	}
}

// --- Unit Tests: Options ---

func TestWithoutCaching_DisablesCache(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithoutCaching(),
	)
	if !s.cachingDisabled {
		t.Error("cachingDisabled should be true")
	}
}

func TestWithCacheTTL_SetsCustomTTL(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithCacheTTL(10*time.Minute),
	)
	if s.cacheTTL != 10*time.Minute {
		t.Errorf("cacheTTL = %v, want 10m", s.cacheTTL)
	}
}

func TestWithoutRateLimiting_Disables(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithoutRateLimiting(),
	)
	if !s.rateLimitDisabled {
		t.Error("rateLimitDisabled should be true")
	}
}

func TestWithRateLimit_SetsCustomValues(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithRateLimit(50, 5),
	)
	if s.rateRPS != 50 {
		t.Errorf("rateRPS = %v, want 50", s.rateRPS)
	}
	if s.rateBurst != 5 {
		t.Errorf("rateBurst = %v, want 5", s.rateBurst)
	}
}

func TestWithMiddleware_AppendsCustom(t *testing.T) {
	noop := func(next ToolHandler) ToolHandler { return next }
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithMiddleware(noop, noop),
	)
	if len(s.customMiddleware) != 2 {
		t.Errorf("customMiddleware count = %d, want 2", len(s.customMiddleware))
	}
}

func TestWithRoleVisibility_SetsFilter(t *testing.T) {
	filter := func(ctx context.Context, toolName string) bool { return true }
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithRoleVisibility(filter),
	)
	if s.roleVisibilityFilter == nil {
		t.Error("roleVisibilityFilter should not be nil")
	}
}

// --- Integration Tests: Full Pipeline ---

// TestPipeline_FullStack verifies that all middleware layers run in the
// correct order on a real tools/call through the HTTP server.
func TestPipeline_FullStack(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s := New("pipeline-test",
		WithVersion("1.0.0"),
		WithLogger(logger),
	)
	s.Tool("echo", "Echoes input", Schema{
		Type:     "object",
		Required: []string{"message"},
		Properties: map[string]Property{
			"message": {Type: "string"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		// Verify context injection works.
		sn := ServerNameFromContext(ctx)
		tn := ToolNameFromContext(ctx)
		sid := SessionIDFromContext(ctx)
		if sn != "pipeline-test" {
			t.Errorf("ServerName = %q, want %q", sn, "pipeline-test")
		}
		if tn != "echo" {
			t.Errorf("ToolName = %q, want %q", tn, "echo")
		}
		if sid == "" {
			t.Error("SessionID is empty")
		}
		return args["message"], nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"message": "hello"},
	}), sid)

	body := readJSON(t, resp)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %v", body)
	}
	content := result["content"].([]any)
	item := content[0].(map[string]any)
	if item["text"] != "hello" {
		t.Errorf("text = %v, want %q", item["text"], "hello")
	}

	// Verify logging middleware produced output.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "tool call completed") {
		t.Errorf("missing log output: %s", logOutput)
	}
	if !strings.Contains(logOutput, "[REDACTED]") {
		t.Errorf("args not redacted in log: %s", logOutput)
	}
}

// TestPipeline_CacheIntegration verifies that caching works through the
// full HTTP dispatch path: second call with same args returns cached result.
func TestPipeline_CacheIntegration(t *testing.T) {
	var callCount atomic.Int32

	s := newTestServer("cache-test",
		WithCacheTTL(5*time.Minute),
	)
	s.Tool("counter", "Counts calls", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return fmt.Sprintf("call-%d", callCount.Add(1)), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// First call: cache miss.
	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "counter",
		"arguments": map[string]any{"a": "b"},
	}), sid)
	body1 := readJSON(t, resp1)
	r1 := body1["result"].(map[string]any)
	c1 := r1["content"].([]any)
	text1 := c1[0].(map[string]any)["text"].(string)
	if text1 != "call-1" {
		t.Errorf("first call = %q, want %q", text1, "call-1")
	}

	// Second call with same args: cache hit.
	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{
		"name":      "counter",
		"arguments": map[string]any{"a": "b"},
	}), sid)
	body2 := readJSON(t, resp2)
	r2 := body2["result"].(map[string]any)
	c2 := r2["content"].([]any)
	text2 := c2[0].(map[string]any)["text"].(string)
	if text2 != "call-1" {
		t.Errorf("second call = %q, want %q (cached)", text2, "call-1")
	}

	// Verify handler was only called once.
	if callCount.Load() != 1 {
		t.Errorf("handler called %d times, want 1", callCount.Load())
	}
}

// TestPipeline_RateLimitIntegration verifies that rate limiting works
// through the full HTTP dispatch path.
func TestPipeline_RateLimitIntegration(t *testing.T) {
	s := newTestServer("rate-test",
		WithRateLimit(0.001, 1), // very low rate, burst of 1
		WithoutCaching(),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// First call: allowed (within burst).
	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "ping"}), sid)
	body1 := readJSON(t, resp1)
	r1, ok := body1["result"].(map[string]any)
	if !ok {
		t.Fatalf("first call should succeed: %v", body1)
	}
	if r1["isError"] == true {
		t.Fatal("first call should not be an error")
	}

	// Second call: rejected (burst exhausted).
	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "ping"}), sid)
	body2 := readJSON(t, resp2)
	r2, ok := body2["result"].(map[string]any)
	if !ok {
		t.Fatalf("second call missing result: %v", body2)
	}
	if r2["isError"] != true {
		t.Fatal("second call should be rate-limited (isError = true)")
	}
	content := r2["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "rate limit exceeded") {
		t.Errorf("error text = %q, want 'rate limit exceeded'", text)
	}
}

// TestPipeline_WithoutCaching verifies that WithoutCaching disables caching.
func TestPipeline_WithoutCaching(t *testing.T) {
	var callCount atomic.Int32
	s := newTestServer("no-cache-test", WithoutCaching())
	s.Tool("counter", "Counts", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return fmt.Sprintf("call-%d", callCount.Add(1)), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	args := map[string]any{"name": "counter", "arguments": map[string]any{"x": "y"}}

	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", args), sid)
	_ = resp1.Body.Close()
	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", args), sid)
	_ = resp2.Body.Close()

	if callCount.Load() != 2 {
		t.Errorf("handler called %d times, want 2 (no cache)", callCount.Load())
	}
}

// TestPipeline_WithoutRateLimiting verifies that WithoutRateLimiting
// disables the rate limiter.
func TestPipeline_WithoutRateLimiting(t *testing.T) {
	s := newTestServer("no-rate-test",
		WithoutRateLimiting(),
		WithoutCaching(),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	// Many rapid calls should all succeed (no rate limiter).
	for i := range 20 {
		resp := doPost(t, ts, rpcBody(t, i+1, "tools/call", map[string]any{"name": "ping"}), sid)
		body := readJSON(t, resp)
		r := body["result"].(map[string]any)
		if r["isError"] == true {
			t.Fatalf("call %d: unexpected rate limit", i)
		}
	}
}

// TestPipeline_CustomMiddlewareInsertion verifies that custom middleware
// injected via WithMiddleware runs at the correct position in the pipeline.
func TestPipeline_CustomMiddlewareInsertion(t *testing.T) {
	var order []string
	var mu sync.Mutex

	customMW := func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			mu.Lock()
			order = append(order, "custom")
			mu.Unlock()
			return next(ctx, args)
		}
	}

	s := newTestServer("custom-mw-test",
		WithMiddleware(customMW),
		WithoutRateLimiting(),
		WithoutCaching(),
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, args map[string]any) (any, error) {
		mu.Lock()
		order = append(order, "handler")
		mu.Unlock()
		return "done", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "echo"}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	mu.Lock()
	defer mu.Unlock()
	// Custom middleware should run before handler (but after context injection).
	if len(order) < 2 {
		t.Fatalf("order = %v, expected at least [custom, handler]", order)
	}
	foundCustom := false
	foundHandler := false
	for _, v := range order {
		if v == "custom" {
			foundCustom = true
		}
		if v == "handler" {
			if !foundCustom {
				t.Error("handler ran before custom middleware")
			}
			foundHandler = true
		}
	}
	if !foundCustom || !foundHandler {
		t.Errorf("order = %v, expected both custom and handler", order)
	}
}

// TestPipeline_ContextAccessorsInHandler verifies that all three context
// accessors (ServerName, ToolName, SessionID) return correct values inside
// a real tool handler dispatched through HTTP.
func TestPipeline_ContextAccessorsInHandler(t *testing.T) {
	s := newTestServer("ctx-test")

	var gotServer, gotTool, gotSession string

	s.Tool("probe", "probes context", Schema{Type: "object"}, func(ctx context.Context, _ map[string]any) (any, error) {
		gotServer = ServerNameFromContext(ctx)
		gotTool = ToolNameFromContext(ctx)
		gotSession = SessionIDFromContext(ctx)
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "probe"}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	if gotServer != "ctx-test" {
		t.Errorf("ServerName = %q, want %q", gotServer, "ctx-test")
	}
	if gotTool != "probe" {
		t.Errorf("ToolName = %q, want %q", gotTool, "probe")
	}
	if gotSession != sid {
		t.Errorf("SessionID = %q, want %q", gotSession, sid)
	}
}

// TestPipeline_LoggingIncludesDuration verifies that the logging middleware
// includes duration in its structured output via the full HTTP path.
func TestPipeline_LoggingIncludesDuration(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s := New("log-test", WithLogger(logger))
	s.Tool("slow", "slow tool", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		time.Sleep(1 * time.Millisecond)
		return "done", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "slow"}), sid)
	_ = resp.Body.Close()

	output := logBuf.String()
	// Parse the log line to verify duration is present and positive.
	var found bool
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "tool call completed") {
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				continue
			}
			dur, ok := entry["duration"]
			if !ok {
				t.Error("duration field missing from log entry")
				continue
			}
			// Duration is logged as a float64 (seconds) by slog JSON handler.
			durVal, ok := dur.(float64)
			if !ok {
				t.Errorf("duration is %T, want float64", dur)
				continue
			}
			if durVal <= 0 {
				t.Errorf("duration = %v, want > 0", durVal)
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no 'tool call completed' log entry found in: %s", output)
	}
}

// TestPipeline_Ordering verifies the full fixed pipeline ordering by
// tracking which middleware fires in which order.
func TestPipeline_Ordering(t *testing.T) {
	var order []string
	var mu sync.Mutex

	trackMW := func(name string) Middleware {
		return func(next ToolHandler) ToolHandler {
			return func(ctx context.Context, args map[string]any) (any, error) {
				mu.Lock()
				order = append(order, name+"-before")
				mu.Unlock()
				result, err := next(ctx, args)
				mu.Lock()
				order = append(order, name+"-after")
				mu.Unlock()
				return result, err
			}
		}
	}

	s := New("order-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithMiddleware(trackMW("custom")),
		// Leave rate limiting and caching on defaults.
	)

	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		mu.Lock()
		order = append(order, "handler")
		mu.Unlock()
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"a": "b"},
	}), sid)
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	// Expected order: rate-limit (no tracking), context (no tracking),
	// cache (no tracking), custom-before, logging (no tracking), handler,
	// logging (no tracking), custom-after, cache (no tracking), ...
	// We can verify custom runs between cache and logging by checking that
	// "custom-before" comes before "handler" and "custom-after" comes after.
	if len(order) < 3 {
		t.Fatalf("order has only %d entries: %v", len(order), order)
	}

	customBeforeIdx := -1
	handlerIdx := -1
	customAfterIdx := -1
	for i, v := range order {
		switch v {
		case "custom-before":
			customBeforeIdx = i
		case "handler":
			handlerIdx = i
		case "custom-after":
			customAfterIdx = i
		}
	}

	if customBeforeIdx == -1 || handlerIdx == -1 || customAfterIdx == -1 {
		t.Fatalf("missing expected entries in order: %v", order)
	}
	if customBeforeIdx >= handlerIdx {
		t.Errorf("custom-before (%d) should be before handler (%d)", customBeforeIdx, handlerIdx)
	}
	if customAfterIdx <= handlerIdx {
		t.Errorf("custom-after (%d) should be after handler (%d)", customAfterIdx, handlerIdx)
	}
}

// TestPipeline_CacheNotSharedAcrossTools verifies that the cache is
// keyed per-tool, not globally.
func TestPipeline_CacheNotSharedAcrossTools(t *testing.T) {
	var tool1Count, tool2Count atomic.Int32

	s := newTestServer("cache-isolation")
	s.Tool("tool1", "first", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return fmt.Sprintf("t1-%d", tool1Count.Add(1)), nil
	})
	s.Tool("tool2", "second", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return fmt.Sprintf("t2-%d", tool2Count.Add(1)), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	// Call tool1
	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "tool1",
		"arguments": map[string]any{"x": "1"},
	}), sid)
	body1 := readJSON(t, resp1)
	r1 := body1["result"].(map[string]any)
	c1 := r1["content"].([]any)
	text1 := c1[0].(map[string]any)["text"].(string)

	// Call tool2 with same args
	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{
		"name":      "tool2",
		"arguments": map[string]any{"x": "1"},
	}), sid)
	body2 := readJSON(t, resp2)
	r2 := body2["result"].(map[string]any)
	c2 := r2["content"].([]any)
	text2 := c2[0].(map[string]any)["text"].(string)

	if text1 == text2 {
		t.Errorf("tools should have different cache entries: tool1=%q, tool2=%q", text1, text2)
	}
	if text1 != "t1-1" {
		t.Errorf("tool1 result = %q, want %q", text1, "t1-1")
	}
	if text2 != "t2-1" {
		t.Errorf("tool2 result = %q, want %q", text2, "t2-1")
	}
}

// TestPipeline_ErrorsAreNotCachedViaHTTP verifies that errors returned by
// tool handlers are not cached when accessed through the full HTTP path.
func TestPipeline_ErrorsAreNotCachedViaHTTP(t *testing.T) {
	var callCount atomic.Int32

	s := newTestServer("no-cache-errors")
	s.Tool("flaky", "errors", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		n := callCount.Add(1)
		if n == 1 {
			return nil, fmt.Errorf("transient error")
		}
		return "recovered", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	// First call: error (should NOT be cached).
	resp1 := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "flaky"}), sid)
	body1 := readJSON(t, resp1)
	r1 := body1["result"].(map[string]any)
	if r1["isError"] != true {
		t.Fatal("first call should be an error")
	}

	// Second call: success (handler called again because error wasn't cached).
	resp2 := doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "flaky"}), sid)
	body2 := readJSON(t, resp2)
	r2 := body2["result"].(map[string]any)
	if r2["isError"] == true {
		t.Fatal("second call should succeed (error not cached)")
	}
	c2 := r2["content"].([]any)
	text2 := c2[0].(map[string]any)["text"].(string)
	if text2 != "recovered" {
		t.Errorf("text = %q, want %q", text2, "recovered")
	}
}

// TestPipeline_RateLimitConcurrent verifies that the rate limiter
// correctly enforces limits under concurrent access.
func TestPipeline_RateLimitConcurrent(t *testing.T) {
	s := newTestServer("concurrent-rate",
		WithRateLimit(0.001, 3), // burst of 3, essentially no replenishment
		WithoutCaching(),
	)
	s.Tool("ping", "pong", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "pong", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()
	sid := initAndActivate(t, ts)

	// Fire 10 concurrent requests; only 3 should succeed.
	var wg sync.WaitGroup
	var successCount, errorCount atomic.Int32

	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			resp := doPost(t, ts, rpcBody(t, id+1, "tools/call", map[string]any{"name": "ping"}), sid)
			body := readJSON(t, resp)
			r := body["result"].(map[string]any)
			if r["isError"] == true {
				errorCount.Add(1)
			} else {
				successCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	if successCount.Load() > 3 {
		t.Errorf("success count = %d, want <= 3 (burst limit)", successCount.Load())
	}
	if errorCount.Load() < 7 {
		t.Errorf("error count = %d, want >= 7", errorCount.Load())
	}
}

// TestPipeline_ExistingEndToEndStillWorks verifies that the middleware
// pipeline does not break the existing E2E flow (initialize -> tools/list
// -> tools/call).
func TestPipeline_ExistingEndToEndStillWorks(t *testing.T) {
	s := newTestServer("compat-test", WithVersion("1.0.0"))
	s.Tool("greet", "Greets", Schema{
		Type:     "object",
		Required: []string{"name"},
		Properties: map[string]Property{
			"name": {Type: "string"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		return fmt.Sprintf("Hello, %s!", args["name"]), nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	// Step 1: initialize
	resp := doPost(t, ts, rpcBody(t, 1, "initialize", nil), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status %d", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	_ = resp.Body.Close()

	// Step 1b: activate session
	resp = doPost(t, ts, rpcBody(t, nil, "notifications/initialized", nil), sid)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Step 2: tools/list
	resp = doPost(t, ts, rpcBody(t, 2, "tools/list", nil), sid)
	body := readJSON(t, resp)
	result := body["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools count = %d, want 1", len(tools))
	}

	// Step 3: tools/call
	resp = doPost(t, ts, rpcBody(t, 3, "tools/call", map[string]any{
		"name":      "greet",
		"arguments": map[string]any{"name": "World"},
	}), sid)
	body = readJSON(t, resp)
	result = body["result"].(map[string]any)
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if text != "Hello, World!" {
		t.Errorf("text = %q, want %q", text, "Hello, World!")
	}
}
