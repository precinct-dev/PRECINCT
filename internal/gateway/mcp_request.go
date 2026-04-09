// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// MCP Request Type Detection - RFA-j2d.6
// Provides request type classification for MCP JSON-RPC requests. Used by the
// response processing pipeline to route responses through the appropriate UI
// control functions (capability gating, CSP mediation, resource controls).
//
// This is a gateway-level abstraction that wraps the already-extracted
// method and params from the JSON-RPC body (parsed by extractMCPMethodAndParams).
// It does NOT duplicate the middleware.MCPRequest struct -- that struct serves
// tool registry verification; this one serves response routing.
package gateway

import "strings"

// MCPRequestInfo holds the parsed JSON-RPC method and params extracted from
// an MCP request body. Used for request type detection in the response
// processing pipeline. Created from the output of extractMCPMethodAndParams.
type MCPRequestInfo struct {
	Method string
	Params map[string]interface{}
}

// NewMCPRequestInfo creates an MCPRequestInfo from a parsed method and params.
func NewMCPRequestInfo(method string, params map[string]interface{}) MCPRequestInfo {
	return MCPRequestInfo{
		Method: method,
		Params: params,
	}
}

// IsToolsList returns true if the request is a tools/list JSON-RPC method call.
func (r MCPRequestInfo) IsToolsList() bool {
	return r.Method == "tools/list"
}

// IsResourceRead returns true if the request is a resources/read JSON-RPC method call.
func (r MCPRequestInfo) IsResourceRead() bool {
	return r.Method == "resources/read"
}

// IsUIResource returns true if the request's resource URI has the ui:// scheme.
// Only meaningful when IsResourceRead() is true. Returns false if no URI is
// present in the params.
func (r MCPRequestInfo) IsUIResource() bool {
	uri := r.ResourceURI()
	return strings.HasPrefix(uri, "ui://")
}

// ResourceURI extracts the resource URI from params.uri.
// Returns "" if not present or not a string.
func (r MCPRequestInfo) ResourceURI() string {
	if r.Params == nil {
		return ""
	}
	if uri, ok := r.Params["uri"].(string); ok {
		return uri
	}
	return ""
}
