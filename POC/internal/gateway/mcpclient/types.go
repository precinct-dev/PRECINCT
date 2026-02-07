// Package mcpclient provides a minimal MCP Streamable HTTP client.
// RFA-9ol: Walking skeleton -- just enough for tools/call through the gateway.
package mcpclient

import "encoding/json"

// JSONRPCRequest is a JSON-RPC 2.0 request envelope for MCP.
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCNotification is a JSON-RPC 2.0 notification (no id field).
// Used for notifications/initialized in the MCP handshake.
type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// JSONRPCResponse is a JSON-RPC 2.0 response envelope from MCP.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolCallParams represents the params for a tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// InitializeParams represents the params for an initialize request per MCP spec 2025-03-26.
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

// ClientCapabilities represents the client's declared capabilities.
// Minimal for this walking skeleton.
type ClientCapabilities struct{}

// ClientInfo identifies the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
