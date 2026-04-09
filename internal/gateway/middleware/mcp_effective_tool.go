// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParsedMCPRequest is a lightweight, shared representation of a JSON-RPC request
// used across middleware for consistent extraction of the "effective" tool name.
//
// The key requirement is MCP spec compliance:
//   - Tool invocations use method="tools/call" with params.name=<tool_name>
//   - Legacy/demo mode may use method=<tool_name> directly
//
// RFA-6fse.1: Single source of truth for tool name extraction.
type ParsedMCPRequest struct {
	RPCMethod string
	Params    map[string]interface{}
}

// ParseMCPRequestBody parses a JSON-RPC request body into ParsedMCPRequest.
// If the body is not valid JSON or not an MCP request, the caller should treat
// this as "not parseable" and usually pass through unchanged.
func ParseMCPRequestBody(body []byte) (*ParsedMCPRequest, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	var req MCPRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	return &ParsedMCPRequest{
		RPCMethod: req.Method,
		Params:    req.Params,
	}, nil
}

// ---------------------------------------------------------------------------
// Request Type Flags (RFA-6fse.1)
//
// The gateway uses multiple MCP protocol-level methods (tools/list, resources/read, etc.)
// in addition to tool invocations. We expose request-type helpers here so every
// middleware layer can make consistent decisions without re-implementing parsing.
// ---------------------------------------------------------------------------

func (r *ParsedMCPRequest) IsNotification() bool {
	return r != nil && strings.HasPrefix(r.RPCMethod, "notifications/")
}

// EffectiveToolName returns the tool name that policy/registry/risk checks
// should evaluate for this request.
//
// Rules:
//   - method="tools/call": tool name is params.name (required by MCP spec)
//   - legacy/demo mode: tool name is method itself
//   - optional backwards compat: params.tool as a fallback when method is empty
//     (non-standard; maintained to avoid breaking older demos/tests)
func (r *ParsedMCPRequest) EffectiveToolName() (string, error) {
	if r == nil {
		return "", fmt.Errorf("nil request")
	}

	// Spec-compliant tools/call envelope.
	if r.RPCMethod == "tools/call" {
		if r.Params == nil {
			return "", fmt.Errorf("invalid tools/call: missing params")
		}
		if name, ok := r.Params["name"].(string); ok && name != "" {
			return name, nil
		}
		// Backward-compat fallback: some legacy callers used params.tool.
		if name, ok := r.Params["tool"].(string); ok && name != "" {
			return name, nil
		}
		return "", fmt.Errorf("invalid tools/call: missing params.name")
	}

	// Legacy/demo mode: direct tool name as JSON-RPC method.
	if r.RPCMethod != "" {
		return r.RPCMethod, nil
	}

	// Non-standard fallback: method empty but params.tool present.
	if r.Params != nil {
		if name, ok := r.Params["tool"].(string); ok && name != "" {
			return name, nil
		}
	}

	return "", nil
}

// IsToolsCall returns true if the JSON-RPC envelope is the MCP spec tools/call.
func (r *ParsedMCPRequest) IsToolsCall() bool {
	return r != nil && r.RPCMethod == "tools/call"
}

func (r *ParsedMCPRequest) IsToolsList() bool {
	return r != nil && r.RPCMethod == "tools/list"
}

func (r *ParsedMCPRequest) IsResourcesRead() bool {
	return r != nil && r.RPCMethod == "resources/read"
}

func (r *ParsedMCPRequest) IsResourcesList() bool {
	return r != nil && r.RPCMethod == "resources/list"
}

func (r *ParsedMCPRequest) IsPromptsList() bool {
	return r != nil && r.RPCMethod == "prompts/list"
}

func (r *ParsedMCPRequest) IsPromptsGet() bool {
	return r != nil && r.RPCMethod == "prompts/get"
}

func (r *ParsedMCPRequest) IsSamplingCreateMessage() bool {
	return r != nil && r.RPCMethod == "sampling/createMessage"
}

func (r *ParsedMCPRequest) IsInitialize() bool {
	return r != nil && r.RPCMethod == "initialize"
}

func (r *ParsedMCPRequest) IsPing() bool {
	return r != nil && r.RPCMethod == "ping"
}

// ToolCallArguments returns params.arguments for tools/call when present.
// Not all middleware needs arguments today, but we centralize extraction so
// future policy layers can use a consistent interpretation.
func (r *ParsedMCPRequest) ToolCallArguments() map[string]interface{} {
	if r == nil || r.Params == nil {
		return nil
	}
	if args, ok := r.Params["arguments"].(map[string]interface{}); ok {
		return args
	}
	return nil
}

// EffectiveToolParams returns the params that belong to the effective tool call.
//
// For spec tools/call, the actual tool arguments live under params.arguments.
// For legacy direct-method calls, the JSON-RPC params are already tool args.
func (r *ParsedMCPRequest) EffectiveToolParams() map[string]interface{} {
	if r == nil {
		return nil
	}
	if r.RPCMethod == "tools/call" {
		if args := r.ToolCallArguments(); args != nil {
			return args
		}
		return map[string]interface{}{}
	}
	return r.Params
}
