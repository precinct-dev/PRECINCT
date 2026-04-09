// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Response Firewall - RFA-qq0.16
// Intercepts tool responses AFTER they return from the upstream MCP server
// but BEFORE sending back to the agent.
//
// Classification behavior:
//   - public:    Pass response through unchanged
//   - internal:  Pass response through, log classification in audit
//   - sensitive: Replace raw data with a handle ($DATA{ref:...,exp:...}) + summary
//
// Handle-ized responses prevent sensitive data from being returned to the agent,
// which could later be exfiltrated through legitimate channels.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ResponseClassification represents the data sensitivity level of a tool
type ResponseClassification string

const (
	ClassificationPublic    ResponseClassification = "public"
	ClassificationInternal  ResponseClassification = "internal"
	ClassificationSensitive ResponseClassification = "sensitive"
)

// HandleStore defines the interface for storing and retrieving handle data.
// This avoids a circular dependency between the gateway and middleware packages.
type HandleStore interface {
	Store(rawData []byte, spiffeID, toolName string) (string, error)
}

// HandleizedResponse is the JSON structure returned to agents for sensitive tools.
// The agent receives this instead of the raw response data.
type HandleizedResponse struct {
	Classification string `json:"classification"`
	DataHandle     string `json:"data_handle"`
	Summary        string `json:"summary"`
}

var marshalHandleizedResponse = json.Marshal

// responseCapture wraps http.ResponseWriter to capture the response body and status
// before it reaches the client, allowing the response firewall to inspect and
// potentially replace the response.
type responseCapture struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
		written:        false,
	}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.written = true
	// Capture but do not forward yet
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if !rc.written {
		rc.statusCode = http.StatusOK
		rc.written = true
	}
	return rc.body.Write(b)
}

func (rc *responseCapture) Header() http.Header {
	return rc.ResponseWriter.Header()
}

// flushTo writes the captured response to the actual ResponseWriter
func (rc *responseCapture) flushTo(w http.ResponseWriter) {
	w.WriteHeader(rc.statusCode)
	_, _ = w.Write(rc.body.Bytes())
}

// ClassifyTool determines the response classification for a tool based on its
// risk_level in the tool registry.
//
// Mapping:
//   - "low"      -> public
//   - "medium"   -> internal
//   - "high"     -> sensitive
//   - "critical" -> sensitive
//   - unknown    -> internal (conservative default)
func ClassifyTool(registry *ToolRegistry, toolName string) ResponseClassification {
	toolDef, exists := registry.GetToolDefinition(toolName)
	if !exists {
		// Unknown tool - treat as internal (conservative)
		return ClassificationInternal
	}

	switch toolDef.RiskLevel {
	case "low":
		return ClassificationPublic
	case "medium":
		return ClassificationInternal
	case "high", "critical":
		return ClassificationSensitive
	default:
		return ClassificationInternal
	}
}

// ResponseFirewall wraps a handler to intercept and classify tool responses.
// For sensitive-classified tools, raw response data is stored in the handle store
// and replaced with a handle + summary.
//
// This function wraps the proxy handler (it is NOT a middleware in the chain).
// It sits between the middleware chain and the actual proxy to upstream.
func ResponseFirewall(next http.Handler, registry *ToolRegistry, store HandleStore, ttlSeconds int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RFA-m6j.2: Create OTel span for response firewall
		ctx, span := tracer.Start(r.Context(), "gateway.response_firewall",
			trace.WithAttributes(
				attribute.String("mcp.gateway.middleware", "response_firewall"),
				attribute.Int("mcp.gateway.step", 14),
			),
		)
		defer span.End()

		// Extract tool name from request body (already captured by BodyCapture)
		toolName := extractToolName(ctx)
		if toolName == "" {
			// No tool name found - pass through unchanged
			span.SetAttributes(
				attribute.Int("handles_created", 0),
				attribute.Bool("data_handleized", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no tool name"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Classify the tool
		classification := ClassifyTool(registry, toolName)

		switch classification {
		case ClassificationPublic:
			// Pass through unchanged
			span.SetAttributes(
				attribute.Int("handles_created", 0),
				attribute.Bool("data_handleized", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "public classification"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))

		case ClassificationInternal:
			// Pass through, audit logging happens in the audit middleware
			slog.Info("internal tool response", "tool", toolName)
			span.SetAttributes(
				attribute.Int("handles_created", 0),
				attribute.Bool("data_handleized", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "internal classification"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))

		case ClassificationSensitive:
			// Capture the response
			capture := newResponseCapture(w)
			next.ServeHTTP(capture, r.WithContext(ctx))

			// If the upstream returned an error, pass it through as-is
			if capture.statusCode >= 400 {
				span.SetAttributes(
					attribute.Int("handles_created", 0),
					attribute.Bool("data_handleized", false),
					attribute.String("mcp.result", "allowed"),
					attribute.String("mcp.reason", "upstream error passthrough"),
				)
				capture.flushTo(w)
				return
			}

			// Get SPIFFE ID for handle binding
			spiffeID := GetSPIFFEID(ctx)

			// Store raw data in handle store
			ref, err := store.Store(capture.body.Bytes(), spiffeID, toolName)
			if err != nil {
				slog.Error("failed to store handle", "error", err)
				span.SetAttributes(
					attribute.Int("handles_created", 0),
					attribute.Bool("data_handleized", false),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "handle_store_unavailable"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusServiceUnavailable, GatewayError{
					Code:           ErrResponseHandleStoreUnavailable,
					Message:        "Sensitive response could not be secured because handle storage is unavailable.",
					ReasonCode:     "handle_store_unavailable",
					Middleware:     "response_firewall",
					MiddlewareStep: 14,
					Remediation:    "Restore handle storage availability, then retry the request.",
				})
				return
			}

			// Build handle-ized response
			handleStr := formatDataHandle(ref, ttlSeconds)
			handleResp := HandleizedResponse{
				Classification: string(ClassificationSensitive),
				DataHandle:     handleStr,
				Summary:        fmt.Sprintf("Response data from %s stored securely. Use the handle to request approved views (aggregates, redacted rows).", toolName),
			}

			respJSON, err := marshalHandleizedResponse(handleResp)
			if err != nil {
				slog.Error("failed to marshal handle response", "error", err)
				span.SetAttributes(
					attribute.Int("handles_created", 0),
					attribute.Bool("data_handleized", false),
					attribute.String("mcp.result", "denied"),
					attribute.String("mcp.reason", "handleization_failed"),
				)
				WriteGatewayError(w, r.WithContext(ctx), http.StatusInternalServerError, GatewayError{
					Code:           ErrResponseHandleizationFailed,
					Message:        "Sensitive response could not be transformed into a secure handleized envelope.",
					ReasonCode:     "handleization_failed",
					Middleware:     "response_firewall",
					MiddlewareStep: 14,
					Remediation:    "Review response-firewall serialization path and retry the request.",
				})
				return
			}

			span.SetAttributes(
				attribute.Int("handles_created", 1),
				attribute.Bool("data_handleized", true),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "data handleized"),
			)

			// Send handle-ized response instead of raw data.
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Response-Classification", "sensitive")
			w.Header().Set("X-Data-Handle", handleStr)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respJSON)

		default:
			// Unknown classification - pass through
			span.SetAttributes(
				attribute.Int("handles_created", 0),
				attribute.Bool("data_handleized", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "unknown classification"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

// extractToolName gets the tool name from the request body stored in context
func extractToolName(ctx context.Context) string {
	body := GetRequestBody(ctx)
	if len(body) == 0 {
		return ""
	}

	parsed, err := ParseMCPRequestBody(body)
	if err != nil {
		return ""
	}

	toolName, err := parsed.EffectiveToolName()
	if err != nil {
		// Response firewall is response-path only; if the request is malformed,
		// earlier middleware should have rejected it. Here we fail open.
		return ""
	}
	return toolName
}

// formatDataHandle creates the standard handle format: $DATA{ref:<hex>,exp:<seconds>}
func formatDataHandle(ref string, ttlSeconds int) string {
	return fmt.Sprintf("$DATA{ref:%s,exp:%d}", ref, ttlSeconds)
}
