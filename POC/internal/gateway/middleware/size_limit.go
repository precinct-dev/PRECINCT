package middleware

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// RequestSizeLimit enforces maximum request body size
func RequestSizeLimit(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 1
		ctx, span := tracer.Start(r.Context(), "gateway.request_size_limit",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 1),
				attribute.String("mcp.gateway.middleware", "request_size_limit"),
			),
		)
		defer span.End()

		// Apply size limit using http.MaxBytesReader
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
