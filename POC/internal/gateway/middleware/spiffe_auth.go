package middleware

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// SPIFFEAuth validates SPIFFE identity
// In dev mode: reads from X-SPIFFE-ID header (placeholder)
// In prod mode: would extract from mTLS cert (not implemented in skeleton)
func SPIFFEAuth(next http.Handler, mode string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 3
		ctx, span := tracer.Start(r.Context(), "gateway.spiffe_auth",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 3),
				attribute.String("mcp.gateway.middleware", "spiffe_auth"),
			),
		)
		defer span.End()

		var spiffeID string

		if mode == "dev" {
			// Dev mode: read from header
			spiffeID = r.Header.Get("X-SPIFFE-ID")
			if spiffeID == "" {
				http.Error(w, "Missing X-SPIFFE-ID header", http.StatusUnauthorized)
				return
			}

			// Basic validation: must start with spiffe://
			if !strings.HasPrefix(spiffeID, "spiffe://") {
				http.Error(w, "Invalid SPIFFE ID format", http.StatusUnauthorized)
				return
			}
		} else {
			// Prod mode: would extract from mTLS cert
			// For skeleton, this is a no-op pass-through
			spiffeID = "spiffe://poc.local/unknown/prod"
		}

		// Record the SPIFFE ID as a span attribute
		span.SetAttributes(attribute.String("mcp.spiffe_id", spiffeID))

		// Add SPIFFE ID to context
		ctx = WithSPIFFEID(ctx, spiffeID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
