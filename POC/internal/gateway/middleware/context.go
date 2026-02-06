package middleware

import (
	"context"
)

// Context keys for request-scoped data
type contextKey string

const (
	contextKeySessionID        contextKey = "session_id"
	contextKeyDecisionID       contextKey = "decision_id"
	contextKeyTraceID          contextKey = "trace_id"
	contextKeySPIFFEID         contextKey = "spiffe_id"
	contextKeyRequestBody      contextKey = "request_body"
	contextKeyToolHashVerified contextKey = "tool_hash_verified"
	contextKeyOPADecisionID    contextKey = "opa_decision_id"
	contextKeySecurityFlags    contextKey = "security_flags"
	contextKeySessionContext   contextKey = "session_context_engine"
	contextKeyUIEnabled        contextKey = "ui_enabled"        // RFA-j2d.7: MCP-UI enabled flag
	contextKeyUICallOrigin     contextKey = "ui_call_origin"    // RFA-j2d.7: "model" or "app"
	contextKeyUIAppToolCalls   contextKey = "ui_app_tool_calls" // RFA-j2d.7: app session tool call count
	contextKeyUIResourceURI    contextKey = "ui_resource_uri"   // RFA-j2d.7: ui:// resource URI
)

// GetSessionID retrieves session ID from context
func GetSessionID(ctx context.Context) string {
	if v := ctx.Value(contextKeySessionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithSessionID adds session ID to context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, contextKeySessionID, sessionID)
}

// GetDecisionID retrieves decision ID from context
func GetDecisionID(ctx context.Context) string {
	if v := ctx.Value(contextKeyDecisionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithDecisionID adds decision ID to context
func WithDecisionID(ctx context.Context, decisionID string) context.Context {
	return context.WithValue(ctx, contextKeyDecisionID, decisionID)
}

// GetTraceID retrieves trace ID from context
func GetTraceID(ctx context.Context) string {
	if v := ctx.Value(contextKeyTraceID); v != nil {
		return v.(string)
	}
	return ""
}

// WithTraceID adds trace ID to context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKeyTraceID, traceID)
}

// GetSPIFFEID retrieves SPIFFE ID from context
func GetSPIFFEID(ctx context.Context) string {
	if v := ctx.Value(contextKeySPIFFEID); v != nil {
		return v.(string)
	}
	return ""
}

// WithSPIFFEID adds SPIFFE ID to context
func WithSPIFFEID(ctx context.Context, spiffeID string) context.Context {
	return context.WithValue(ctx, contextKeySPIFFEID, spiffeID)
}

// GetRequestBody retrieves captured request body from context
func GetRequestBody(ctx context.Context) []byte {
	if v := ctx.Value(contextKeyRequestBody); v != nil {
		return v.([]byte)
	}
	return nil
}

// WithRequestBody adds request body to context
func WithRequestBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, contextKeyRequestBody, body)
}

// GetToolHashVerified retrieves tool hash verification status from context
func GetToolHashVerified(ctx context.Context) bool {
	if v := ctx.Value(contextKeyToolHashVerified); v != nil {
		return v.(bool)
	}
	return false
}

// WithToolHashVerified adds tool hash verification status to context
func WithToolHashVerified(ctx context.Context, verified bool) context.Context {
	return context.WithValue(ctx, contextKeyToolHashVerified, verified)
}

// GetOPADecisionID retrieves OPA decision ID from context
func GetOPADecisionID(ctx context.Context) string {
	if v := ctx.Value(contextKeyOPADecisionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithOPADecisionID adds OPA decision ID to context
func WithOPADecisionID(ctx context.Context, decisionID string) context.Context {
	return context.WithValue(ctx, contextKeyOPADecisionID, decisionID)
}

// GetSecurityFlags retrieves security flags from context
func GetSecurityFlags(ctx context.Context) []string {
	if v := ctx.Value(contextKeySecurityFlags); v != nil {
		return v.([]string)
	}
	return nil
}

// WithSecurityFlags adds security flags to context
func WithSecurityFlags(ctx context.Context, flags []string) context.Context {
	return context.WithValue(ctx, contextKeySecurityFlags, flags)
}

// GetUIEnabled retrieves MCP-UI enabled flag from context (RFA-j2d.7)
func GetUIEnabled(ctx context.Context) bool {
	if v := ctx.Value(contextKeyUIEnabled); v != nil {
		return v.(bool)
	}
	return false
}

// WithUIEnabled adds MCP-UI enabled flag to context (RFA-j2d.7)
func WithUIEnabled(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, contextKeyUIEnabled, enabled)
}

// GetUICallOrigin retrieves the UI call origin from context (RFA-j2d.7)
func GetUICallOrigin(ctx context.Context) string {
	if v := ctx.Value(contextKeyUICallOrigin); v != nil {
		return v.(string)
	}
	return ""
}

// WithUICallOrigin adds UI call origin to context (RFA-j2d.7)
func WithUICallOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, contextKeyUICallOrigin, origin)
}

// GetUIAppToolCalls retrieves the app session tool call count from context (RFA-j2d.7)
func GetUIAppToolCalls(ctx context.Context) int {
	if v := ctx.Value(contextKeyUIAppToolCalls); v != nil {
		return v.(int)
	}
	return 0
}

// WithUIAppToolCalls adds app session tool call count to context (RFA-j2d.7)
func WithUIAppToolCalls(ctx context.Context, count int) context.Context {
	return context.WithValue(ctx, contextKeyUIAppToolCalls, count)
}

// GetUIResourceURI retrieves the UI resource URI from context (RFA-j2d.7)
func GetUIResourceURI(ctx context.Context) string {
	if v := ctx.Value(contextKeyUIResourceURI); v != nil {
		return v.(string)
	}
	return ""
}

// WithUIResourceURI adds UI resource URI to context (RFA-j2d.7)
func WithUIResourceURI(ctx context.Context, uri string) context.Context {
	return context.WithValue(ctx, contextKeyUIResourceURI, uri)
}
