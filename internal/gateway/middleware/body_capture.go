// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"io"
	"log/slog"
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

		// Honor caller-provided session IDs so session-aware controls can
		// accumulate risk across requests. Generate one only when absent.
		// OC-3nnm: Validate caller-provided session IDs are valid UUIDs to
		// prevent injection of crafted session IDs. Invalid values are replaced
		// with a fresh UUID and logged as a warning.
		sessionID := r.Header.Get("X-Session-ID")
		if sessionID == "" {
			sessionID = r.Header.Get("Mcp-Session-Id")
		}
		if sessionID == "" {
			sessionID = uuid.New().String()
		} else if _, err := uuid.Parse(sessionID); err != nil {
			slog.Warn("invalid session ID format rejected, generating new ID",
				"provided_session_id", sessionID,
				"error", err,
			)
			sessionID = uuid.New().String()
		}
		decisionID := uuid.New().String()
		traceID := uuid.New().String()

		// Add IDs to context
		ctx = WithSessionID(ctx, sessionID)
		ctx = WithDecisionID(ctx, decisionID)
		ctx = WithTraceID(ctx, traceID)

		// Capture request body if present.
		// RFA-zxf: Size validation is handled by RequestSizeLimit (step 1).
		// This middleware only captures the body for downstream use. Any read
		// error here is a genuine I/O problem, not a size violation.
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				WriteGatewayError(w, r.WithContext(ctx), http.StatusBadRequest, GatewayError{
					Code:           "body_read_failed",
					Message:        "Failed to read request body",
					Middleware:     "body_capture",
					MiddlewareStep: 2,
					Remediation:    "Check for network issues or malformed request body.",
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
