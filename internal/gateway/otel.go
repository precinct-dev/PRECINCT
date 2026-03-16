package gateway

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// InitTracer initializes the OpenTelemetry TracerProvider with an OTLP gRPC exporter.
// When endpoint is empty, no TracerProvider is registered and the default no-op
// tracer is used -- spans are silently discarded (graceful no-op per AC6).
//
// Returns a shutdown function that flushes pending spans and releases resources.
// The caller MUST invoke the shutdown function during graceful shutdown.
func InitTracer(ctx context.Context, endpoint, serviceName string) (func(context.Context) error, error) {
	if endpoint == "" {
		// No endpoint configured -- return a no-op shutdown.
		return func(context.Context) error { return nil }, nil
	}

	if serviceName == "" {
		serviceName = "precinct-gateway"
	}

	// Create OTLP gRPC exporter targeting the OTel Collector.
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(), // Collector is on the internal Docker network
		otlptracegrpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Build resource with service identity attributes.
	// Use NewSchemaless to avoid schema URL conflicts between resource.Default()
	// and specific semconv versions.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			attribute.String("service.name", serviceName),
			attribute.String("service.version", "2.0.0"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTel resource: %w", err)
	}

	// Create TracerProvider with batch span processor for production throughput.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Register as the global TracerProvider so middleware tracer picks it up.
	otel.SetTracerProvider(tp)

	// RFA-m6j.3: Register W3C Trace Context propagator globally.
	// This enables cross-service trace correlation: the gateway injects
	// traceparent/tracestate headers into outbound requests to MCP servers
	// and SPIKE Nexus, linking all spans into a single distributed trace.
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// TracingTransport wraps an http.RoundTripper to inject W3C Trace Context
// (traceparent/tracestate) headers into every outbound request.
// This enables distributed trace correlation: spans from the gateway are
// linked to spans from downstream services (MCP server, SPIKE Nexus).
//
// RFA-m6j.3: Cross-service trace context propagation.
type TracingTransport struct {
	Base http.RoundTripper
}

// RoundTrip injects the trace context from the request's context into the
// outbound HTTP headers, then delegates to the base transport.
func (t *TracingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use the globally registered propagator (set in InitTracer).
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(req.Context(), propagation.HeaderCarrier(req.Header))

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// NewTracingTransport creates a TracingTransport wrapping the given base transport.
// If base is nil, http.DefaultTransport is used.
func NewTracingTransport(base http.RoundTripper) *TracingTransport {
	return &TracingTransport{Base: base}
}
