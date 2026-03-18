package mcpserver

// Middleware wraps a ToolHandler to add cross-cutting behavior such as
// rate limiting, caching, context injection, or logging. Middleware is
// applied at the tool-call level only -- it does not wrap initialize,
// tools/list, or other JSON-RPC methods.
type Middleware func(ToolHandler) ToolHandler

// compose chains two middleware together so that outer runs first (wraps
// inner). The resulting Middleware applies outer, then inner, then the
// handler.
func compose(outer, inner Middleware) Middleware {
	return func(next ToolHandler) ToolHandler {
		return outer(inner(next))
	}
}

// buildPipeline assembles an ordered slice of Middleware into a single
// Middleware. The first element in the slice is the outermost wrapper
// (runs first on the way in, last on the way out). An empty slice
// returns a pass-through that invokes the handler directly.
func buildPipeline(mws []Middleware) Middleware {
	if len(mws) == 0 {
		return func(h ToolHandler) ToolHandler { return h }
	}
	// Start from the innermost (last) middleware and fold outward.
	pipeline := mws[len(mws)-1]
	for i := len(mws) - 2; i >= 0; i-- {
		pipeline = compose(mws[i], pipeline)
	}
	return pipeline
}
