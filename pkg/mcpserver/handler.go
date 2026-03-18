package mcpserver

import "context"

// ToolHandler is the callback invoked when a tools/call request targets a
// registered tool. The args map contains the deserialized JSON parameters
// from the request. The returned value is serialized as the text content of
// the MCP response. Returning a non-nil error produces an isError response.
type ToolHandler func(ctx context.Context, args map[string]any) (any, error)

// Schema describes the JSON Schema for a tool's input parameters.
type Schema struct {
	Type       string              `json:"type"`
	Required   []string            `json:"required,omitempty"`
	Properties map[string]Property `json:"properties,omitempty"`
}

// Property describes a single property within a Schema.
type Property struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// toolEntry holds a registered tool's metadata and handler.
type toolEntry struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema Schema      `json:"inputSchema"`
	Handler     ToolHandler `json:"-"`
}

// Tool registers a tool with the server. It can be called before or after
// Run, but tools registered after Run will not be visible to clients until
// the next tools/list request.
func (s *Server) Tool(name, description string, schema Schema, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = append(s.tools, toolEntry{
		Name:        name,
		Description: description,
		InputSchema: schema,
		Handler:     handler,
	})
}
