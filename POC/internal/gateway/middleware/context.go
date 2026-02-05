package middleware

import (
	"context"
)

// Context keys for request-scoped data
type contextKey string

const (
	contextKeySessionID   contextKey = "session_id"
	contextKeyDecisionID  contextKey = "decision_id"
	contextKeyTraceID     contextKey = "trace_id"
	contextKeySPIFFEID    contextKey = "spiffe_id"
	contextKeyRequestBody contextKey = "request_body"
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
