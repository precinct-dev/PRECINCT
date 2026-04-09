// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import "context"

// BackendAdapter is a convenience type for callers who want a uniform way to
// forward MCP tool calls to an existing HTTP/gRPC backend. It is NOT used by
// the mcpserver framework itself -- the server dispatches tools exclusively
// through [ToolHandler] callbacks. BackendAdapter exists so that consumers can
// standardise their bridging code without inventing their own interface each
// time.
//
// A typical implementation wraps an HTTP client and maps (method, path, params)
// to a backend request, returning the decoded response body.
//
//	type myBackend struct{ client *http.Client; base string }
//
//	func (b *myBackend) Call(ctx context.Context, method, path string, params map[string]any) (any, error) {
//	    body, _ := json.Marshal(params)
//	    req, _ := http.NewRequestWithContext(ctx, method, b.base+path, bytes.NewReader(body))
//	    resp, err := b.client.Do(req)
//	    if err != nil { return nil, err }
//	    defer resp.Body.Close()
//	    var result any
//	    json.NewDecoder(resp.Body).Decode(&result)
//	    return result, nil
//	}
type BackendAdapter interface {
	// Call forwards a request to a backend service. method is the HTTP method
	// (GET, POST, ...), path is the resource path, and params carries the
	// deserialized tool arguments. The returned value is serialized as the
	// MCP text content of the tool response.
	Call(ctx context.Context, method, path string, params map[string]any) (any, error)
}
