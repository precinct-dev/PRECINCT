// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Package mcpclient provides an MCP Streamable HTTP client.
// RFA-9ol: Walking skeleton. RFA-8rd: Full session management, SSE, lifecycle.
// RFA-0dz: Transport interface + Legacy SSE transport + auto-detection.
package mcpclient

import (
	"context"
	"encoding/json"
)

// Transport is the common interface implemented by both StreamableHTTPTransport
// and LegacySSETransport. It abstracts the MCP transport layer so the gateway
// can use either transport interchangeably.
//
// RFA-0dz: Introduced for auto-detection -- the gateway uses Transport rather
// than a concrete type, and DetectTransport chooses the right implementation.
type Transport interface {
	// Send sends a JSON-RPC request and returns the response.
	Send(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error)
	// Close terminates the transport connection and cleans up resources.
	Close(ctx context.Context) error
}

// SessionState tracks the lifecycle of an MCP session.
type SessionState int

const (
	// SessionUninitialized means no initialize handshake has been performed.
	SessionUninitialized SessionState = iota
	// SessionActive means the session is initialized and the server has assigned a session ID.
	SessionActive
	// SessionExpired means the server returned 404, indicating the session is no longer valid.
	SessionExpired
)

// String returns a human-readable label for the session state.
func (s SessionState) String() string {
	switch s {
	case SessionUninitialized:
		return "uninitialized"
	case SessionActive:
		return "active"
	case SessionExpired:
		return "expired"
	default:
		return "unknown"
	}
}

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

// ClientCapabilities represents the client's declared capabilities per MCP spec.
// RFA-8rd: Enhanced with roots and sampling fields.
type ClientCapabilities struct {
	// Roots indicates whether the client supports providing filesystem roots.
	Roots *RootsCapability `json:"roots,omitempty"`
	// Sampling indicates whether the client supports LLM sampling requests.
	Sampling *SamplingCapability `json:"sampling,omitempty"`
}

// RootsCapability declares the client's roots support.
type RootsCapability struct {
	// ListChanged indicates whether the client emits notifications/roots/list_changed.
	ListChanged bool `json:"listChanged,omitempty"`
}

// SamplingCapability declares the client's sampling support.
// Empty struct per spec -- presence alone signals support.
type SamplingCapability struct{}

// ClientInfo identifies the MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerCapabilities represents the server's declared capabilities from the
// initialize response. RFA-8rd: Parsed from the initialize result.
type ServerCapabilities struct {
	// Tools indicates whether the server supports tools.
	Tools *ToolsCapability `json:"tools,omitempty"`
	// Resources indicates whether the server supports resources.
	Resources *ResourcesCapability `json:"resources,omitempty"`
	// Prompts indicates whether the server supports prompts.
	Prompts *PromptsCapability `json:"prompts,omitempty"`
	// Logging indicates whether the server supports logging.
	Logging *LoggingCapability `json:"logging,omitempty"`
}

// ToolsCapability declares the server's tools support.
type ToolsCapability struct {
	// ListChanged indicates whether the server emits notifications/tools/list_changed.
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability declares the server's resources support.
type ResourcesCapability struct {
	// Subscribe indicates whether the server supports resource subscriptions.
	Subscribe bool `json:"subscribe,omitempty"`
	// ListChanged indicates whether the server emits notifications/resources/list_changed.
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability declares the server's prompts support.
type PromptsCapability struct {
	// ListChanged indicates whether the server emits notifications/prompts/list_changed.
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability declares the server's logging support.
// Empty struct per spec -- presence alone signals support.
type LoggingCapability struct{}

// ServerInfo identifies the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult is the parsed result from an initialize response.
// RFA-8rd: Used to extract server capabilities and protocol version.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}
