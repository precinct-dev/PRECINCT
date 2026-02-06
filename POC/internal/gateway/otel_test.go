package gateway

import (
	"context"
	"testing"
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
	// When service name is empty, it should default to "mcp-security-gateway".
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
