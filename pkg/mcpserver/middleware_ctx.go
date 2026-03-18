package mcpserver

import "context"

// contextKey is an unexported type used as context value keys to prevent
// collisions with keys defined in other packages.
type contextKey int

const (
	keyServerName contextKey = iota
	keyToolName
	keySessionID
)

// ServerNameFromContext extracts the server name from the context. Returns
// an empty string if the context was not enriched by the context injection
// middleware.
func ServerNameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyServerName).(string)
	return v
}

// ToolNameFromContext extracts the tool name from the context. Returns an
// empty string if the context was not enriched by the context injection
// middleware.
func ToolNameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyToolName).(string)
	return v
}

// SessionIDFromContext extracts the session ID from the context. Returns
// an empty string if the context was not enriched by the context injection
// middleware.
func SessionIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keySessionID).(string)
	return v
}

// newContextMiddleware returns a Middleware that injects server name,
// tool name, and session ID into the request context. The tool name and
// session ID are provided by the dispatch path at call time via
// withToolCallContext; the server name is fixed at construction.
func newContextMiddleware(serverName string) Middleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			ctx = context.WithValue(ctx, keyServerName, serverName)
			return next(ctx, args)
		}
	}
}

// withToolCallContext enriches a context with the tool name and session ID
// for a specific tools/call invocation. This is called from the dispatch
// path, before the middleware pipeline runs, so that all middleware
// (including context injection and caching) can access these values.
func withToolCallContext(ctx context.Context, toolName, sessionID string) context.Context {
	ctx = context.WithValue(ctx, keyToolName, toolName)
	ctx = context.WithValue(ctx, keySessionID, sessionID)
	return ctx
}
