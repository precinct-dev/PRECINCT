// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// RequestSizeLimit enforces maximum request body size.
// RFA-zxf: The size check is performed eagerly by reading the body in this
// middleware (step 1), rather than deferring to http.MaxBytesReader which
// would trigger the error during body_capture (step 2). This ensures the
// audit log correctly attributes size rejections to step 1.
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

		// Eagerly check body size if a body is present.
		// Read up to maxBytes+1 to detect whether the body exceeds the limit.
		if r.Body != nil && r.ContentLength != 0 {
			limited := io.LimitReader(r.Body, maxBytes+1)
			bodyBytes, err := io.ReadAll(limited)
			_ = r.Body.Close()

			if err != nil {
				// I/O error during read (network failure, etc.)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusBadRequest, GatewayError{
					Code:           ErrRequestTooLarge,
					Message:        "Failed to read request body",
					Middleware:     "request_size_limit",
					MiddlewareStep: 1,
					Remediation:    "Check for network issues or reduce request body size.",
				})
				return
			}

			if int64(len(bodyBytes)) > maxBytes {
				WriteGatewayError(w, r.WithContext(ctx), http.StatusRequestEntityTooLarge, GatewayError{
					Code:           ErrRequestTooLarge,
					Message:        "Request body exceeds maximum allowed size",
					Middleware:     "request_size_limit",
					MiddlewareStep: 1,
					Details: map[string]any{
						"max_bytes":    maxBytes,
						"actual_bytes": len(bodyBytes),
					},
					Remediation: fmt.Sprintf("Reduce the request body size. Maximum allowed: %d bytes.", maxBytes),
				})
				return
			}

			// Body is within limits -- restore it for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
