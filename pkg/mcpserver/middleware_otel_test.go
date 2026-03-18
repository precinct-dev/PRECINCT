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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// newTestTracer returns a TracerProvider with an in-memory span exporter
// and the exporter itself for inspecting recorded spans.
func newTestTracer() (*sdktrace.TracerProvider, *tracetest.InMemoryExporter) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	return tp, exporter
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
	handler(ctx, nil)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "tool.name", "echo")
}

func TestOTelMiddleware_RecordsDurationMs(t *testing.T) {
	tp, exporter := newTestTracer()
	defer tp.Shutdown(context.Background())

	mw := newOTelMiddleware(tp.Tracer(tracerName))
	ctx := withToolCallContext(context.Background(), "slow-tool", "s1")

	handler := mw(func(_ context.Context, _ map[string]any) (any, error) {
		return "ok", nil
	})
	handler(ctx, nil)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	var found bool
	for _, attr := range spans[0].Attributes {
		if string(attr.Key) == "tool.duration_ms" {
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
	handler(ctx, nil)

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
	}

	assertAttribute(t, spans[0].Attributes, "tool.outcome", "success")

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
	assertAttribute(t, span.Attributes, "tool.outcome", "error")

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
	handler(ctx, nil)

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

	sid := initSession(t, ts)
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
	assertAttribute(t, span.Attributes, "tool.name", "echo")
	assertAttribute(t, span.Attributes, "tool.outcome", "success")
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

	sid := initSession(t, ts)
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
	assertAttribute(t, span.Attributes, "tool.outcome", "error")
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

	sid := initSession(t, ts)
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

	sid := initSession(t, ts)

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

	sid := initSession(t, ts)

	resp := doPost(t, ts, rpcBody(t, 1, "tools/call", map[string]any{"name": "tool-a"}), sid)
	resp.Body.Close()
	resp = doPost(t, ts, rpcBody(t, 2, "tools/call", map[string]any{"name": "tool-b"}), sid)
	resp.Body.Close()

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

	sid := initSession(t, ts)
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
	if len(spans) != 1 {
		t.Fatalf("span count = %d, want 1", len(spans))
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

	sid := initSession(t, ts)
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

// Verify test helpers from mcpserver_test.go are accessible.
// The helpers (rpcBody, doPost, readJSON, initSession, newTestServer)
// are defined in mcpserver_test.go and are package-level, so they are
// accessible here since this is also package mcpserver.
var _ = strings.Contains // suppress unused import lint (strings used in error messages)
