// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// MCP protocol version implemented by this server.
const protocolVersion = "2025-03-26"

// jsonrpcVersion is the JSON-RPC protocol version string.
const jsonrpcVersion = "2.0"

// --- JSON-RPC request/response types (unexported) ---

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any            `json:"result,omitempty"`
	Error   *jsonrpcError  `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// --- MCP-specific response types ---

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    capabilities   `json:"capabilities"`
	ServerInfo      serverInfoResp `json:"serverInfo"`
}

type capabilities struct {
	Tools toolsCapability `json:"tools"`
}

type toolsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type serverInfoResp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolsListResult struct {
	Tools []toolDescription `json:"tools"`
}

type toolDescription struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema Schema `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// --- Dispatch ---

// dispatch routes a parsed JSON-RPC request to the appropriate handler
// method and returns the response payload. Notifications (no ID) return a
// nil result, indicating the caller should send HTTP 200 with no body.
func (s *Server) dispatch(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "notifications/initialized":
		// Notifications are fire-and-forget; no JSON-RPC response body.
		return nil
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	default:
		return &jsonrpcResponse{
			JSONRPC: jsonrpcVersion,
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    codeMethodNotFound,
				Message: fmt.Sprintf("method not found: %s", req.Method),
			},
		}
	}
}

func (s *Server) handleInitialize(req *jsonrpcRequest) *jsonrpcResponse {
	return &jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      req.ID,
		Result: initializeResult{
			ProtocolVersion: protocolVersion,
			Capabilities: capabilities{
				Tools: toolsCapability{ListChanged: false},
			},
			ServerInfo: serverInfoResp{
				Name:    s.name,
				Version: s.version,
			},
		},
	}
}

func (s *Server) handleToolsList(req *jsonrpcRequest) *jsonrpcResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tools := make([]toolDescription, len(s.tools))
	for i, t := range s.tools {
		tools[i] = toolDescription{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		}
	}

	return &jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      req.ID,
		Result:  toolsListResult{Tools: tools},
	}
}

func (s *Server) handleToolsCall(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	var params toolCallParams
	if req.Params == nil {
		return &jsonrpcResponse{
			JSONRPC: jsonrpcVersion,
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    codeInvalidParams,
				Message: "params required for tools/call",
			},
		}
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &jsonrpcResponse{
			JSONRPC: jsonrpcVersion,
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    codeInvalidParams,
				Message: fmt.Sprintf("invalid params: %v", err),
			},
		}
	}

	s.mu.RLock()
	var handler ToolHandler
	for _, t := range s.tools {
		if t.Name == params.Name {
			handler = t.Handler
			break
		}
	}
	s.mu.RUnlock()

	if handler == nil {
		return &jsonrpcResponse{
			JSONRPC: jsonrpcVersion,
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    codeInvalidParams,
				Message: fmt.Sprintf("unknown tool: %s", params.Name),
			},
		}
	}

	// Enrich context with per-call metadata (tool name, session ID) before
	// entering the middleware pipeline. The session ID is extracted from the
	// context set by handleJSONRPC.
	sessionID := SessionIDFromContext(ctx)
	ctx = withToolCallContext(ctx, params.Name, sessionID)

	// Wrap the handler through the middleware pipeline.
	wrapped := s.wrappedHandler(handler)

	result, err := wrapped(ctx, params.Arguments)
	if err != nil {
		return &jsonrpcResponse{
			JSONRPC: jsonrpcVersion,
			ID:      req.ID,
			Result: toolCallResult{
				Content: []toolContent{{Type: "text", Text: err.Error()}},
				IsError: true,
			},
		}
	}

	text := fmt.Sprintf("%v", result)
	return &jsonrpcResponse{
		JSONRPC: jsonrpcVersion,
		ID:      req.ID,
		Result: toolCallResult{
			Content: []toolContent{{Type: "text", Text: text}},
		},
	}
}
