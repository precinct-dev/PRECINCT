package middleware

import (
	"bytes"
	"io"
	"net/http"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BodyCapture captures the request body and makes it available in context
// Also generates session, decision, and trace IDs
func BodyCapture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.1: Create OTel span for step 2
		ctx, span := tracer.Start(r.Context(), "gateway.body_capture",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 2),
				attribute.String("mcp.gateway.middleware", "body_capture"),
			),
		)
		defer span.End()

		// Generate IDs for this request
		sessionID := uuid.New().String()
		decisionID := uuid.New().String()
		traceID := uuid.New().String()

		// Add IDs to context
		ctx = WithSessionID(ctx, sessionID)
		ctx = WithDecisionID(ctx, decisionID)
		ctx = WithTraceID(ctx, traceID)

		// Capture request body if present
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				WriteGatewayError(w, r.WithContext(ctx), http.StatusBadRequest, GatewayError{
					Code:           ErrRequestTooLarge,
					Message:        "Failed to read request body",
					Middleware:     "body_capture",
					MiddlewareStep: 2,
					Remediation:    "Reduce the request body size or check for network issues.",
				})
				return
			}
			_ = r.Body.Close()

			// Store body in context
			ctx = WithRequestBody(ctx, bodyBytes)

			// Restore body for downstream handlers
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Continue with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
