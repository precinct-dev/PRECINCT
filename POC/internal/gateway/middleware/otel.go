package middleware

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracer is the package-level OTel tracer used by all middleware in the gateway.
// It produces spans under the "mcp-security-gateway" instrumentation scope.
// When no TracerProvider is registered (OTEL_EXPORTER_OTLP_ENDPOINT is empty),
// otel.Tracer returns a no-op tracer that does not export spans.
var tracer = otel.Tracer("mcp-security-gateway", trace.WithInstrumentationVersion("2.0.0"))
