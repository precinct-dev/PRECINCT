package middleware

import (
	"bytes"
	"io"
	"net/http"

	"github.com/google/uuid"
)

// BodyCapture captures the request body and makes it available in context
// Also generates session, decision, and trace IDs
func BodyCapture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate IDs for this request
		sessionID := uuid.New().String()
		decisionID := uuid.New().String()
		traceID := uuid.New().String()

		// Add IDs to context
		ctx := r.Context()
		ctx = WithSessionID(ctx, sessionID)
		ctx = WithDecisionID(ctx, decisionID)
		ctx = WithTraceID(ctx, traceID)

		// Capture request body if present
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
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
