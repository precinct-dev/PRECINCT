// Unified JSON error response envelope for all gateway middleware.
// RFA-tj9.1: Every middleware error MUST use WriteGatewayError instead of
// http.Error or ad-hoc JSON. This gives agent developers a single parsing path.
package middleware

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

// GatewayError is the unified error envelope returned by every middleware
// rejection in the gateway. Agent SDKs parse this single structure.
type GatewayError struct {
	Code           string         `json:"code"`
	Message        string         `json:"message"`
	ReasonCode     string         `json:"reason_code,omitempty"`
	Middleware     string         `json:"middleware"`
	MiddlewareStep int            `json:"middleware_step"`
	DecisionID     string         `json:"decision_id"`
	TraceID        string         `json:"trace_id"`
	Details        map[string]any `json:"details,omitempty"`
	Remediation    string         `json:"remediation,omitempty"`
	DocsURL        string         `json:"docs_url,omitempty"`
}

// WriteGatewayError serializes a GatewayError as JSON and writes it as the
// HTTP response with the given status code. The Content-Type is always
// application/json. If the caller has not yet populated DecisionID or TraceID,
// this function attempts to fill them from the request context.
func WriteGatewayError(w http.ResponseWriter, r *http.Request, httpCode int, ge GatewayError) {
	// Populate decision_id and trace_id from request context if not already set.
	if ge.DecisionID == "" {
		ge.DecisionID = GetDecisionID(r.Context())
	}
	if ge.TraceID == "" {
		// Prefer the OTel span's trace ID for correlation with distributed traces,
		// falling back to the gateway-assigned trace ID stored in context.
		if spanCtx := trace.SpanFromContext(r.Context()).SpanContext(); spanCtx.HasTraceID() {
			ge.TraceID = spanCtx.TraceID().String()
		} else {
			ge.TraceID = GetTraceID(r.Context())
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(ge)
}
