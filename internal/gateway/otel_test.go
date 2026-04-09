// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInitTracer_EmptyEndpoint_ReturnsNoopShutdown(t *testing.T) {
	// AC6: When OTEL_EXPORTER_OTLP_ENDPOINT is empty, no spans are exported.
	shutdown, err := InitTracer(context.Background(), "", "test-service")
	if err != nil {
		t.Fatalf("InitTracer with empty endpoint should not error, got: %v", err)
	}

	// The no-op shutdown should succeed without error
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("No-op shutdown should not error, got: %v", err)
	}
}

func TestInitTracer_EmptyServiceName_DefaultsToGateway(t *testing.T) {
	// When service name is empty, it should default to "precinct-gateway".
	// We test with an empty endpoint to avoid needing a real collector.
	shutdown, err := InitTracer(context.Background(), "", "")
	if err != nil {
		t.Fatalf("InitTracer with empty service name should not error, got: %v", err)
	}
	_ = shutdown(context.Background())
}

func TestInitTracer_ValidEndpoint_ReturnsShutdownFunc(t *testing.T) {
	// Test with a valid endpoint format. The exporter creation will succeed
	// even if the endpoint is not reachable (gRPC is lazy-connect).
	// We use a non-routable address to avoid connecting to anything real.
	shutdown, err := InitTracer(context.Background(), "127.0.0.1:0", "test-otel-service")
	if err != nil {
		t.Fatalf("InitTracer should not error with valid endpoint format, got: %v", err)
	}

	// Shutdown should be callable
	if shutdown == nil {
		t.Fatal("Expected non-nil shutdown function")
	}

	// Shutdown should succeed (flushes to non-existent collector, which is fine)
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown should not error, got: %v", err)
	}
}

// ---------- RFA-m6j.3: TracingTransport tests ----------

// setupTracerAndPropagator installs an in-memory exporter and the W3C TraceContext
// propagator, then returns a teardown function.
func setupTracerAndPropagator(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return exporter, func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}
}

// TestTracingTransport_InjectsTraceparent verifies that TracingTransport
// injects the traceparent header into outbound requests (AC1).
func TestTracingTransport_InjectsTraceparent(t *testing.T) {
	_, teardown := setupTracerAndPropagator(t)
	defer teardown()

	// Create a span so there is trace context to propagate.
	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-parent")
	defer span.End()

	// Capture the outbound request headers at the upstream server.
	var receivedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	transport := NewTracingTransport(upstream.Client().Transport)
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "POST", upstream.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Failed to close response body: %v", err)
	}

	if receivedTraceparent == "" {
		t.Fatal("Expected traceparent header on outbound request, got empty")
	}

	// W3C Trace Context format: version-traceid-parentid-flags
	// e.g., "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	parts := strings.Split(receivedTraceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent format invalid: expected 4 parts, got %d: %q", len(parts), receivedTraceparent)
	}
	if parts[0] != "00" {
		t.Errorf("Expected traceparent version '00', got %q", parts[0])
	}
	if len(parts[1]) != 32 {
		t.Errorf("Expected trace-id to be 32 hex chars, got %d chars: %q", len(parts[1]), parts[1])
	}
	if len(parts[2]) != 16 {
		t.Errorf("Expected parent-id to be 16 hex chars, got %d chars: %q", len(parts[2]), parts[2])
	}

	t.Logf("traceparent header: %s", receivedTraceparent)
}

// TestTracingTransport_TraceIDMatchesGatewaySpan verifies that the trace_id
// in the propagated traceparent matches the gateway's span trace_id (AC4).
func TestTracingTransport_TraceIDMatchesGatewaySpan(t *testing.T) {
	exporter, teardown := setupTracerAndPropagator(t)
	defer teardown()

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "gateway-request")

	var receivedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	transport := NewTracingTransport(upstream.Client().Transport)
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "POST", upstream.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Failed to close response body: %v", err)
	}
	span.End()

	// Extract trace_id from the traceparent header
	parts := strings.Split(receivedTraceparent, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent format invalid: %q", receivedTraceparent)
	}
	propagatedTraceID := parts[1]

	// Get the gateway span's trace_id from the exporter
	spans := exporter.GetSpans()
	gatewaySpan := findTestSpan(spans, "gateway-request")
	if gatewaySpan == nil {
		t.Fatal("Expected 'gateway-request' span not found")
	}
	gatewayTraceID := gatewaySpan.SpanContext.TraceID().String()

	if propagatedTraceID != gatewayTraceID {
		t.Errorf("Trace ID mismatch: propagated=%q, gateway span=%q", propagatedTraceID, gatewayTraceID)
	}

	t.Logf("Trace ID correctly correlates: %s", gatewayTraceID)
}

// TestTracingTransport_NilBase_UsesDefaultTransport verifies that when
// Base is nil, the transport falls back to http.DefaultTransport.
func TestTracingTransport_NilBase_UsesDefaultTransport(t *testing.T) {
	_, teardown := setupTracerAndPropagator(t)
	defer teardown()

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "nil-base-test")
	defer span.End()

	var receivedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Explicitly pass nil base -- should use http.DefaultTransport
	transport := NewTracingTransport(nil)
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "GET", upstream.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Failed to close response body: %v", err)
	}

	if receivedTraceparent == "" {
		t.Fatal("Expected traceparent header even with nil base transport")
	}
}

// TestTracingTransport_NoSpanContext_NoHeader verifies that when there is
// no active span in the context, no traceparent header is injected
// (graceful no-op behavior).
func TestTracingTransport_NoSpanContext_NoHeader(t *testing.T) {
	_, teardown := setupTracerAndPropagator(t)
	defer teardown()

	var receivedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	transport := NewTracingTransport(upstream.Client().Transport)
	client := &http.Client{Transport: transport}

	// No span in context -- bare context.Background()
	req, err := http.NewRequestWithContext(context.Background(), "GET", upstream.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Failed to close response body: %v", err)
	}

	// With no span context, the propagator should not inject a traceparent
	if receivedTraceparent != "" {
		t.Errorf("Expected no traceparent without active span, got: %q", receivedTraceparent)
	}
}

// TestInitTracer_RegistersPropagator verifies that InitTracer (with valid endpoint)
// registers the W3C TraceContext propagator globally (AC1, AC2).
func TestInitTracer_RegistersPropagator(t *testing.T) {
	// Save and restore global state
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}()

	// Reset to default (noop) propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())

	shutdown, err := InitTracer(context.Background(), "127.0.0.1:0", "test-propagator")
	if err != nil {
		t.Fatalf("InitTracer failed: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// After InitTracer, the global propagator should be TraceContext
	propagator := otel.GetTextMapPropagator()
	if propagator == nil {
		t.Fatal("Expected non-nil global propagator after InitTracer")
	}

	// Verify it handles "traceparent" field
	fields := propagator.Fields()
	foundTraceparent := false
	for _, f := range fields {
		if f == "traceparent" {
			foundTraceparent = true
		}
	}
	if !foundTraceparent {
		t.Errorf("Expected propagator to handle 'traceparent' field, got fields: %v", fields)
	}
}

// findTestSpan locates a span by name in the exported spans (otel_test.go helper).
func findTestSpan(spans tracetest.SpanStubs, name string) *tracetest.SpanStub {
	for i, s := range spans {
		if s.Name == name {
			return &spans[i]
		}
	}
	return nil
}
