// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// helper: POST a JSON-RPC request and return the response body.
func postRPC(t *testing.T, ts *httptest.Server, method string, params any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequest(http.MethodPost, ts.URL+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, respBody
}

// initSession performs the initialize handshake and returns the session ID.
func initSession(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp, body := postRPC(t, ts, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "1.0"},
	}, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Initialize returned status %d: %s", resp.StatusCode, string(body))
	}

	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("Initialize did not return Mcp-Session-Id header")
	}

	// Verify JSON-RPC response structure
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse initialize response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("Initialize returned error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		t.Fatal("Initialize returned nil result")
	}

	// Verify server capabilities
	var result map[string]any
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		t.Fatalf("Failed to parse initialize result: %v", err)
	}
	if result["protocolVersion"] != "2025-03-26" {
		t.Errorf("Expected protocolVersion=2025-03-26, got %v", result["protocolVersion"])
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo == nil || serverInfo["name"] != "mock-mcp-server" {
		t.Errorf("Expected serverInfo.name=mock-mcp-server, got %v", serverInfo)
	}

	// Send notifications/initialized
	resp2, _ := postRPC(t, ts, "notifications/initialized", nil, map[string]string{
		"Mcp-Session-Id": sid,
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized returned status %d", resp2.StatusCode)
	}

	return sid
}

func TestInitializeHandshake(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)
	if sid == "" {
		t.Error("Session ID should not be empty after initialization")
	}
	t.Logf("Session initialized: %s", sid)
}

func TestToolsCall_TavilySearch(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	// Call tools/call with tavily_search
	resp, body := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "tavily_search",
		"arguments": map[string]any{"query": "AI security"},
	}, map[string]string{"Mcp-Session-Id": sid})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("tools/call returned error: %s", rpcResp.Error.Message)
	}

	// Verify the result contains canned search data
	var result map[string]any
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}
	firstItem, _ := content[0].(map[string]any)
	text, _ := firstItem["text"].(string)
	if text == "" {
		t.Error("Expected non-empty text in first content item")
	}
	// Verify the canned data contains expected search results
	if !bytes.Contains([]byte(text), []byte("AI Security Best Practices")) {
		t.Errorf("Expected canned search results to contain 'AI Security Best Practices', got: %s", text[:min(len(text), 200)])
	}
	t.Logf("tools/call result preview: %s", text[:min(len(text), 100)])
}

func TestDirectToolCall_TavilySearch(t *testing.T) {
	// Test the gateway's mode: method="tavily_search" directly
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	resp, body := postRPC(t, ts, "tavily_search", map[string]any{
		"query": "test query",
	}, map[string]string{"Mcp-Session-Id": sid})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Direct tavily_search returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("Direct call returned error: %s", rpcResp.Error.Message)
	}
	if rpcResp.Result == nil {
		t.Fatal("Expected non-nil result from direct tavily_search call")
	}
}

func TestToolsCall_Echo(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	echoArgs := map[string]any{"hello": "world", "count": 42}
	resp, body := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": echoArgs,
	}, map[string]string{"Mcp-Session-Id": sid})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call echo returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("tools/call echo returned error: %s", rpcResp.Error.Message)
	}

	// Verify echo returns the input
	var result map[string]any
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array")
	}
	firstItem, _ := content[0].(map[string]any)
	text, _ := firstItem["text"].(string)
	if !bytes.Contains([]byte(text), []byte("hello")) {
		t.Errorf("Echo should contain input args, got: %s", text)
	}
}

func TestToolsList(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	resp, body := postRPC(t, ts, "tools/list", nil, map[string]string{
		"Mcp-Session-Id": sid,
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("tools/list returned error: %s", rpcResp.Error.Message)
	}

	var result map[string]any
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatal("Expected tools array in result")
	}
	if len(tools) != 3 {
		t.Fatalf("Expected 3 tools, got %d", len(tools))
	}

	// Verify tool names
	var toolNames []string
	for _, tool := range tools {
		toolMap, _ := tool.(map[string]any)
		name, _ := toolMap["name"].(string)
		toolNames = append(toolNames, name)
	}
	if toolNames[0] != "tavily_search" || toolNames[1] != "echo" || toolNames[2] != "render-analytics" {
		t.Errorf("Expected tools [tavily_search, echo, render-analytics], got %v", toolNames)
	}
}

func TestWrongSessionID(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Initialize to create a valid session
	_ = initSession(t, ts)

	// Call with wrong session ID
	resp, body := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "tavily_search",
		"arguments": map[string]any{"query": "test"},
	}, map[string]string{"Mcp-Session-Id": "wrong-session-id"})

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for wrong session ID, got %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("Expected error in response for wrong session ID")
	}
	if rpcResp.Error.Code != -32000 {
		t.Errorf("Expected error code -32000, got %d", rpcResp.Error.Code)
	}
}

func TestNoSessionID(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Initialize a session
	_ = initSession(t, ts)

	// Call without session ID header
	resp, body := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "tavily_search",
		"arguments": map[string]any{"query": "test"},
	}, nil)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 for missing session ID, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestSessionTermination(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	// DELETE to terminate session
	req, err := http.NewRequest(http.MethodDelete, ts.URL+"/", nil)
	if err != nil {
		t.Fatalf("Failed to create DELETE request: %v", err)
	}
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("Expected 204 for session termination, got %d", resp.StatusCode)
	}

	// Subsequent call should fail with 404
	resp2, body2 := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "tavily_search",
		"arguments": map[string]any{"query": "test"},
	}, map[string]string{"Mcp-Session-Id": sid})

	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 after session termination, got %d: %s", resp2.StatusCode, string(body2))
	}
}

func TestHealthEndpoint(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 for health check, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("Failed to parse health response: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("Expected status=ok, got %v", result["status"])
	}
}

func TestUnknownTool(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sid := initSession(t, ts)

	// Call a tool that does not exist
	resp, body := postRPC(t, ts, "tools/call", map[string]any{
		"name":      "nonexistent_tool",
		"arguments": map[string]any{},
	}, map[string]string{"Mcp-Session-Id": sid})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 (JSON-RPC error), got %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("Expected JSON-RPC error for unknown tool")
	}
	if rpcResp.Error.Code != -32601 {
		t.Errorf("Expected error code -32601 (method not found), got %d", rpcResp.Error.Code)
	}
}

func TestInvalidJSON(t *testing.T) {
	srv := NewServer()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", bytes.NewReader([]byte("not valid json")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
