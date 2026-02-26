package middleware

import (
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	gwmetrics "github.com/RamXX/agentic_reference_architecture/POC/internal/gateway/metrics"
)

// tracer is the package-level OTel tracer used by all middleware in the gateway.
// It produces spans under the "mcp-security-gateway" instrumentation scope.
// When no TracerProvider is registered (OTEL_EXPORTER_OTLP_ENDPOINT is empty),
// otel.Tracer returns a no-op tracer that does not export spans.
var tracer = otel.Tracer("mcp-security-gateway", trace.WithInstrumentationVersion("2.0.0"))

// meter is the package-level OTel meter used by all middleware in the gateway.
// It produces metrics under the "mcp-security-gateway" instrumentation scope.
// When no MeterProvider is registered, otel.Meter returns a no-op meter.
var meter = otel.Meter("mcp-security-gateway")

// gwMetrics holds the application-defined metric instruments.
// Initialized at package init time. If instrument creation fails (should not
// happen with a valid meter), the error is logged and gwMetrics remains nil;
// middleware checks for nil before recording.
var gwMetrics *gwmetrics.Metrics

func init() {
	m, err := gwmetrics.NewMetrics(meter)
	if err != nil {
		slog.Error("failed to initialize gateway metrics instruments", "error", err)
		return
	}
	gwMetrics = m
}

// GWMetrics returns the package-level metrics instruments for use by
// non-middleware callers (e.g., gateway.go request_total recording).
// Returns nil if metrics initialization failed.
func GWMetrics() *gwmetrics.Metrics {
	return gwMetrics
}
