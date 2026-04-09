// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

type testTracerProvider struct {
	*sdktrace.TracerProvider
}

func (tp testTracerProvider) Shutdown(context.Context) {}

// newTestTracer returns a TracerProvider with an in-memory span exporter
// and the exporter itself for inspecting recorded spans.
func newTestTracer() (testTracerProvider, *tracetest.InMemoryExporter) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	return testTracerProvider{TracerProvider: tp}, exporter
}

func mustCallToolHandler(t *testing.T, handler ToolHandler, ctx context.Context) any {
	t.Helper()
	result, err := handler(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result
}

// --- Unit Tests: OTel Middleware ---

func TestOTelMiddleware_CreatesSpanWithCorrectName(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "my-tool", "session-1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	result, err := handler(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %v, want %q", result, "ok")
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	expectedName := "mcpserver.tools/call.my-tool"
	if span.Name != expectedName {
		t.Errorf("span name = %q, want %q", span.Name, expectedName)
	}
}

func TestOTelMiddleware_RecordsToolNameAttribute(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "echo", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "mcp.tool.name", "echo")
}

func TestOTelMiddleware_RecordsServerNameAttribute(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	// Simulate the context middleware having injected the server name.
	ctx := withToolCallContext(context.Background(), "my-tool", "s1")
	ctx = context.WithValue(ctx, keyServerName, "test-server")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "mcp.server.name", "test-server")
}

func TestOTelMiddleware_RecordsSessionIDAttribute(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "my-tool", "session-xyz")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "mcp.session.id", "session-xyz")
}

func TestOTelMiddleware_RecordsDurationMs(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "slow-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	var found bool
	for _, attr := range spans[0].Attributes {
		if string(attr.Key) == "mcp.tool.duration_ms" {
			if attr.Value.Type() != attribute.FLOAT64 {
				t.Errorf("tool.duration_ms type = %v, want FLOAT64", attr.Value.Type())
			}
			if attr.Value.AsFloat64() < 0 {
				t.Errorf("tool.duration_ms = %v, want >= 0", attr.Value.AsFloat64())
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("tool.duration_ms attribute not found on span")
	}
}

func TestOTelMiddleware_SuccessOutcome(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "ok-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "mcp.tool.outcome", "success")

	if spans[0].Status.Code != codes.Ok {
		t.Errorf("span status = %v, want Ok", spans[0].Status.Code)
	}
}

func TestOTelMiddleware_ErrorSetsSpanStatus(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "fail-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("something broke")
	})
	_, err := handler(ctx, nil)
	if err == nil {
		t.Fatal("expected error")
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	assertAttribute(t, span.Attributes, "mcp.tool.outcome", "error")

	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
	if span.Status.Description != "something broke" {
		t.Errorf("span status description = %q, want %q", span.Status.Description, "something broke")
	}

	// Verify that RecordError was called (events should contain the error).
	var foundErrorEvent bool
	for _, event := range span.Events {
		if event.Name == "exception" {
			foundErrorEvent = true
			break
		}
	}
	if !foundErrorEvent {
		t.Error("expected an exception event from RecordError")
	}
}

func TestOTelMiddleware_PropagatesResultAndError(t *testing.T) {
	tp, _ := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "pass-through", "s1")

	// Success case.
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "the-result", nil
	})
	result, err := handler(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "the-result" {
		t.Errorf("result = %v, want %q", result, "the-result")
	}

	// Error case.
	handler2 := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("fail")
	})
	_, err = handler2(ctx, nil)
	if err == nil || err.Error() != "fail" {
		t.Errorf("error = %v, want %q", err, "fail")
	}
}

func TestOTelMiddleware_SpanContextAvailableInHandler(t *testing.T) {
	tp, _ := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "ctx-check", "s1")

	var spanCtx trace.SpanContext
	handler := mw(func(ctx context.Context, _ map[string]any) (any, error) {
		spanCtx = trace.SpanFromContext(ctx).SpanContext()
		return "ok", nil
	})
	mustCallToolHandler(t, handler, ctx)

	if !spanCtx.IsValid() {
		t.Error("expected valid span context inside handler")
	}
}

// --- Unit Tests: Options ---

func TestWithTracerProvider_SetsProvider(t *testing.T) {
	tp, _ := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
	)
	if s.tracerProvider == nil {
		t.Error("tracerProvider should not be nil")
	}
}

func TestWithoutOTel_DisablesOTel(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithoutOTel(),
	)
	if !s.otelDisabled {
		t.Error("otelDisabled should be true")
	}
}

func TestTracerMethod_UsesCustomProvider(t *testing.T) {
	tp, _ := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
	)
	tracer := s.tracer()
	if tracer == nil {
		t.Fatal("tracer should not be nil")
	}
}

func TestTracerMethod_FallsBackToGlobal(t *testing.T) {
	s := New("test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	// No custom provider set -- should fall back to global.
	tracer := s.tracer()
	if tracer == nil {
		t.Fatal("tracer should not be nil")
	}
}

// --- Integration Tests: OTel through full HTTP pipeline ---

func TestOTelIntegration_SpanCreatedViaHTTP(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("otel-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, args map[string]any) (any, error) {
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"msg": "hello"},
	}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	expectedName := "mcpserver.tools/call.echo"
	if span.Name != expectedName {
		t.Errorf("span name = %q, want %q", span.Name, expectedName)
	}
	assertAttribute(t, span.Attributes, "mcp.tool.name", "echo")
	assertAttribute(t, span.Attributes, "mcp.tool.outcome", "success")
}

func TestOTelIntegration_ErrorSpanViaHTTP(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("otel-err-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("fail", "fails", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("handler error")
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name": "fail",
	}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] != true {
		t.Fatalf("expected isError=true, got %v", r)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
	assertAttribute(t, span.Attributes, "mcp.tool.outcome", "error")
}

func TestOTelIntegration_WithoutOTelDisablesSpans(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("otel-disabled-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutOTel(),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name": "echo",
	}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	spans := exporter.GetSpans()
	if len(spans) != 0 {
		t.Errorf("span count = %d, want 0 (OTel disabled)", len(spans))
	}
}

func TestOTelIntegration_TraceparentPropagation(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	// Register a W3C trace context propagator so the server can extract
	// traceparent headers.
	origPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(origPropagator)

	s := New("trace-prop-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)

	var capturedTraceID trace.TraceID
	s.Tool("probe", "captures trace", Schema{Type: "object"}, func(ctx context.Context, _ map[string]any) (any, error) {
		capturedTraceID = trace.SpanFromContext(ctx).SpanContext().TraceID()
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// Build a tools/call request with a traceparent header.
	reqBody := rpcBody(t, 1, "tools/call", map[string]any{
		"name": "probe",
	})
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/", reqBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sid)
	// W3C traceparent: version-traceID-parentSpanID-flags
	// Using a known trace ID so we can verify propagation.
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	// The trace ID captured inside the handler should match the
	// traceparent we sent.
	expectedTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	if capturedTraceID.String() != expectedTraceID {
		t.Errorf("trace ID = %q, want %q", capturedTraceID.String(), expectedTraceID)
	}

	// Verify the recorded span also has the same trace ID.
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}
	if spans[0].SpanContext.TraceID().String() != expectedTraceID {
		t.Errorf("span trace ID = %q, want %q",
			spans[0].SpanContext.TraceID().String(), expectedTraceID)
	}
}

func TestOTelIntegration_MultipleToolCallsCreateMultipleSpans(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("multi-span-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("tool-a", "first", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "a", nil
	})
	s.Tool("tool-b", "second", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "b", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "tool-a"}), sid)
	_ = resp.Body.Close()
	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "tool-b"}), sid)
	_ = resp.Body.Close()

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("span count = %d, want 2", len(spans))
	}

	names := map[string]bool{}
	for _, span := range spans {
		names[span.Name] = true
	}
	if !names["mcpserver.tools/call.tool-a"] {
		t.Error("missing span for tool-a")
	}
	if !names["mcpserver.tools/call.tool-b"] {
		t.Error("missing span for tool-b")
	}
}

func TestOTelIntegration_ExistingPipelineStillWorks(t *testing.T) {
	// Ensure OTel middleware does not break existing middleware pipeline behavior.
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("compat-otel-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		// Leave caching and rate limiting on defaults to verify they still work.
	)
	s.Tool("echo", "echo", Schema{
		Type: "object",
		Properties: map[string]Property{
			"msg": {Type: "string"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		// Verify context injection still works alongside OTel.
		if ServerNameFromContext(ctx) != "compat-otel-test" {
			t.Errorf("ServerName = %q, want %q", ServerNameFromContext(ctx), "compat-otel-test")
		}
		if ToolNameFromContext(ctx) != "echo" {
			t.Errorf("ToolName = %q, want %q", ToolNameFromContext(ctx), "echo")
		}
		return args["msg"], nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"msg": "test"},
	}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}
	content := r["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if text != "test" {
		t.Errorf("text = %q, want %q", text, "test")
	}

	spans := exporter.GetSpans()
	// With rate limiting and caching on defaults, we get:
	// middleware.rate_limit + mcpserver.tools/call.echo + middleware.cache = 3 spans.
	var foundToolSpan bool
	for _, span := range spans {
		if span.Name == "mcpserver.tools/call.echo" {
			foundToolSpan = true
		}
	}
	if !foundToolSpan {
		t.Errorf("missing tools/call span, got spans: %v", spanNames(spans))
	}
}

func TestOTelIntegration_NoTraceparentStillCreatesSpan(t *testing.T) {
	// When no traceparent header is present, a new trace should be created.
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	origPropagator := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer otel.SetTextMapPropagator(origPropagator)

	s := New("no-parent-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
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

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	// The span should have a valid (auto-generated) trace ID.
	if !spans[0].SpanContext.TraceID().IsValid() {
		t.Error("expected a valid trace ID even without traceparent header")
	}
}

// --- Unit Tests: Rate Limit Span ---

func TestRateLimitMiddleware_CreatesSpanWhenTracerProvided(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newRateLimitMiddleware(1000, 5, withRateLimitTracer(tp.Tracer(tracerName)))
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	_, err := handler(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	if span.Name != "middleware.rate_limit" {
		t.Errorf("span name = %q, want %q", span.Name, "middleware.rate_limit")
	}
	assertBoolAttribute(t, span.Attributes, "mcp.rate_limit.allowed", true)
}

func TestRateLimitMiddleware_SpanRecordsDenied(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	// Burst of 1, very low rate -- second call should be denied.
	mw := newRateLimitMiddleware(0.001, 1, withRateLimitTracer(tp.Tracer(tracerName)))
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	mustCallToolHandler(t, handler, context.Background()) // allowed
	if _, err := handler(context.Background(), nil); err == nil {
		t.Fatal("expected rate limit denial on second call")
	}

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("span count = %d, want 2", len(spans))
	}

	assertBoolAttribute(t, spans[0].Attributes, "mcp.rate_limit.allowed", true)
	assertBoolAttribute(t, spans[1].Attributes, "mcp.rate_limit.allowed", false)
}

func TestRateLimitMiddleware_NoSpanWithoutTracer(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	// No tracer option -- should not create spans.
	mw := newRateLimitMiddleware(1000, 5)
	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	mustCallToolHandler(t, handler, context.Background())

	spans := exporter.GetSpans()
	if len(spans) != 0 {
		t.Errorf("span count = %d, want 0 (no tracer)", len(spans))
	}
}

// --- Unit Tests: Cache Span ---

func TestCacheMiddleware_CreatesSpanOnMiss(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newCacheMiddleware(5*time.Minute, withCacheTracer(tp.Tracer(tracerName)))
	ctx := withToolCallContext(context.Background(), "tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "result", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	span := spans[0]
	if span.Name != "middleware.cache" {
		t.Errorf("span name = %q, want %q", span.Name, "middleware.cache")
	}
	assertBoolAttribute(t, span.Attributes, "mcp.cache.hit", false)
	assertFloat64AttributeGTE(t, span.Attributes, "mcp.cache.ttl_remaining_s", 0)
}

func TestCacheMiddleware_CreatesSpanOnHit(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newCacheMiddleware(5*time.Minute, withCacheTracer(tp.Tracer(tracerName)))
	ctx := withToolCallContext(context.Background(), "tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "result", nil
	})

	mustCallToolHandler(t, handler, ctx) // miss
	mustCallToolHandler(t, handler, ctx) // hit

	spans := exporter.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("span count = %d, want 2", len(spans))
	}

	// First span: miss.
	assertBoolAttribute(t, spans[0].Attributes, "mcp.cache.hit", false)

	// Second span: hit with positive TTL remaining.
	assertBoolAttribute(t, spans[1].Attributes, "mcp.cache.hit", true)
	assertFloat64AttributeGT(t, spans[1].Attributes, "mcp.cache.ttl_remaining_s", 0)
}

func TestCacheMiddleware_SpanOnError(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newCacheMiddleware(5*time.Minute, withCacheTracer(tp.Tracer(tracerName)))
	ctx := withToolCallContext(context.Background(), "tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return nil, fmt.Errorf("fail")
	})
	if _, err := handler(ctx, nil); err == nil {
		t.Fatal("expected cache middleware to propagate the handler error")
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertBoolAttribute(t, spans[0].Attributes, "mcp.cache.hit", false)
	assertFloat64AttributeEq(t, spans[0].Attributes, "mcp.cache.ttl_remaining_s", 0)
}

func TestCacheMiddleware_NoSpanWithoutTracer(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newCacheMiddleware(5 * time.Minute)
	ctx := withToolCallContext(context.Background(), "tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "result", nil
	})
	mustCallToolHandler(t, handler, ctx)

	spans := exporter.GetSpans()
	if len(spans) != 0 {
		t.Errorf("span count = %d, want 0 (no tracer)", len(spans))
	}
}

// --- Integration Tests: Rate Limit and Cache Spans via HTTP ---

func TestOTelIntegration_RateLimitSpanViaHTTP(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("ratelimit-otel-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		// Leave rate limiting on defaults.
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
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

	// Should have: rate_limit span + OTel tools/call span = 2 spans.
	spans := exporter.GetSpans()
	var foundRateLimit bool
	for _, span := range spans {
		if span.Name == "middleware.rate_limit" {
			foundRateLimit = true
			assertBoolAttribute(t, span.Attributes, "mcp.rate_limit.allowed", true)
		}
	}
	if !foundRateLimit {
		t.Error("missing middleware.rate_limit span")
	}
}

func TestOTelIntegration_CacheSpanViaHTTP(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("cache-otel-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutRateLimiting(),
		// Leave caching on defaults.
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})

	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initAndActivate(t, ts)

	// First call: cache miss.
	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "echo"}), sid)
	body := readJSON(t, resp)
	r := body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	// Second call: cache hit.
	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "echo"}), sid)
	body = readJSON(t, resp)
	r = body["result"].(map[string]any)
	if r["isError"] == true {
		t.Fatalf("unexpected error: %v", r)
	}

	spans := exporter.GetSpans()
	var cacheMissFound, cacheHitFound bool
	for _, span := range spans {
		if span.Name == "middleware.cache" {
			hit := findBoolAttribute(span.Attributes, "mcp.cache.hit")
			if hit != nil && !*hit {
				cacheMissFound = true
			}
			if hit != nil && *hit {
				cacheHitFound = true
				// Verify TTL remaining is positive on a hit.
				assertFloat64AttributeGT(t, span.Attributes, "mcp.cache.ttl_remaining_s", 0)
			}
		}
	}
	if !cacheMissFound {
		t.Error("missing cache miss span")
	}
	if !cacheHitFound {
		t.Error("missing cache hit span")
	}
}

func TestOTelIntegration_ServerNameAndSessionIDViaHTTP(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("attrs-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		WithoutCaching(),
		WithoutRateLimiting(),
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
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

	spans := exporter.GetSpans()
	var otelSpan *tracetest.SpanStub
	for i, span := range spans {
		if span.Name == "mcpserver.tools/call.echo" {
			otelSpan = &spans[i]
			break
		}
	}
	if otelSpan == nil {
		t.Fatal("missing OTel tools/call span")
		return
	}

	assertAttribute(t, otelSpan.Attributes, "mcp.server.name", "attrs-test")
	// Session ID should be non-empty (we do not know the exact value since
	// it is a UUID, but it must be present and match the sid we received).
	assertAttribute(t, otelSpan.Attributes, "mcp.session.id", sid)
}

func TestOTelIntegration_AllSpansPresent(t *testing.T) {
	// With rate limiting, caching, and OTel all enabled, a single tool call
	// should produce spans for rate_limit, cache, and tools/call.
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	s := New("all-spans-test",
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithTracerProvider(tp),
		// Leave everything on defaults.
	)
	s.Tool("echo", "echo", Schema{Type: "object"}, func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
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

	spans := exporter.GetSpans()
	spanNames := map[string]bool{}
	for _, span := range spans {
		spanNames[span.Name] = true
	}

	if !spanNames["middleware.rate_limit"] {
		t.Error("missing middleware.rate_limit span")
	}
	if !spanNames["middleware.cache"] {
		t.Error("missing middleware.cache span")
	}
	if !spanNames["mcpserver.tools/call.echo"] {
		t.Error("missing mcpserver.tools/call.echo span")
	}
}

// --- Helpers ---

// assertAttribute checks that the given attribute slice contains the
// expected key-value pair (string values only).
func assertAttribute(t *testing.T, attrs []attribute.KeyValue, key, want string) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			got := attr.Value.AsString()
			if got != want {
				t.Errorf("attribute %q = %q, want %q", key, got, want)
			}
			return
		}
	}
	t.Errorf("attribute %q not found, want %q", key, want)
}

// assertBoolAttribute checks that the given attribute slice contains
// the expected key with the expected bool value.
func assertBoolAttribute(t *testing.T, attrs []attribute.KeyValue, key string, want bool) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			if attr.Value.Type() != attribute.BOOL {
				t.Errorf("attribute %q type = %v, want BOOL", key, attr.Value.Type())
				return
			}
			got := attr.Value.AsBool()
			if got != want {
				t.Errorf("attribute %q = %v, want %v", key, got, want)
			}
			return
		}
	}
	t.Errorf("attribute %q not found, want %v", key, want)
}

// findBoolAttribute returns a pointer to the bool value for the given key,
// or nil if not found.
func findBoolAttribute(attrs []attribute.KeyValue, key string) *bool {
	for _, attr := range attrs {
		if string(attr.Key) == key {
			v := attr.Value.AsBool()
			return &v
		}
	}
	return nil
}

// assertFloat64AttributeGTE checks that the given float64 attribute exists
// and its value is >= the minimum.
func assertFloat64AttributeGTE(t *testing.T, attrs []attribute.KeyValue, key string, min float64) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			if attr.Value.Type() != attribute.FLOAT64 {
				t.Errorf("attribute %q type = %v, want FLOAT64", key, attr.Value.Type())
				return
			}
			got := attr.Value.AsFloat64()
			if got < min {
				t.Errorf("attribute %q = %v, want >= %v", key, got, min)
			}
			return
		}
	}
	t.Errorf("attribute %q not found", key)
}

// assertFloat64AttributeGT checks that the given float64 attribute exists
// and its value is > the minimum.
func assertFloat64AttributeGT(t *testing.T, attrs []attribute.KeyValue, key string, min float64) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			if attr.Value.Type() != attribute.FLOAT64 {
				t.Errorf("attribute %q type = %v, want FLOAT64", key, attr.Value.Type())
				return
			}
			got := attr.Value.AsFloat64()
			if got <= min {
				t.Errorf("attribute %q = %v, want > %v", key, got, min)
			}
			return
		}
	}
	t.Errorf("attribute %q not found", key)
}

// assertFloat64AttributeEq checks that the given float64 attribute exists
// and its value equals the expected value.
func assertFloat64AttributeEq(t *testing.T, attrs []attribute.KeyValue, key string, want float64) {
	t.Helper()
	for _, attr := range attrs {
		if string(attr.Key) == key {
			if attr.Value.Type() != attribute.FLOAT64 {
				t.Errorf("attribute %q type = %v, want FLOAT64", key, attr.Value.Type())
				return
			}
			got := attr.Value.AsFloat64()
			if got != want {
				t.Errorf("attribute %q = %v, want %v", key, got, want)
			}
			return
		}
	}
	t.Errorf("attribute %q not found", key)
}

// spanNames returns a slice of span names for debugging output.
func spanNames(spans []tracetest.SpanStub) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name
	}
	return names
}

// Verify test helpers from mcpserver_test.go are accessible.
// The helpers (rpcBody, doPost, readJSON, initSession, newTestServer)
// are defined in mcpserver_test.go and are package-level, so they are
// accessible here since this is also package mcpserver.
var _ = strings.Contains // suppress unused import lint (strings used in error messages)
