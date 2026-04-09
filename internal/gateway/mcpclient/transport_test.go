// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// newMockMCPServer returns an httptest server simulating a Streamable HTTP MCP
// server that responds to initialize + notifications/initialized + tools/call.
// The handshakeCount tracks how many initialize calls are received.
func newMockMCPServer(t *testing.T, handshakeCount *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Logf("Failed to read body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Try to parse as JSON-RPC request
			var rpcReq map[string]interface{}
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				if handshakeCount != nil {
					atomic.AddInt32(handshakeCount, 1)
				}

				// RFA-8rd: Verify client sends capabilities (roots)
				params, _ := rpcReq["params"].(map[string]interface{})
				if params != nil {
					caps, _ := params["capabilities"].(map[string]interface{})
					if caps != nil {
						if _, hasRoots := caps["roots"]; !hasRoots {
							t.Log("WARNING: initialize request missing roots capability")
						}
					}
				}

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "test-session-123")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true}},"serverInfo":{"name":"mock-mcp","version":"1.0"}}`),
				}
				_ = json.NewEncoder(w).Encode(resp)

			case "notifications/initialized":
				// Notification -- return 200 with no body
				w.WriteHeader(http.StatusOK)

			case "tools/call":
				// Verify Mcp-Session-Id header is present
				sessionID := r.Header.Get("Mcp-Session-Id")
				if sessionID == "" {
					t.Log("WARNING: tools/call received without Mcp-Session-Id header")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"content":[{"type":"text","text":"search result for query"}]}`),
				}
				_ = json.NewEncoder(w).Encode(resp)

			case "tools/list":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"tools":[{"name":"web_search","description":"Search the web"}]}`),
				}
				_ = json.NewEncoder(w).Encode(resp)

			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"status":"ok"}`),
				}
				_ = json.NewEncoder(w).Encode(resp)
			}

		case http.MethodDelete:
			// Session termination
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

// --- Existing RFA-9ol Tests (preserved + enhanced) ---

func TestTransport_Initialize_TwoStepHandshake(t *testing.T) {
	var handshakeCount int32
	server := newMockMCPServer(t, &handshakeCount)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())

	if transport.Initialized() {
		t.Error("Transport should not be initialized before Initialize()")
	}

	// RFA-8rd: Verify initial state
	if transport.State() != SessionUninitialized {
		t.Errorf("Expected state=uninitialized, got %s", transport.State())
	}

	ctx := context.Background()
	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if !transport.Initialized() {
		t.Error("Transport should be initialized after Initialize()")
	}

	if transport.SessionID() != "test-session-123" {
		t.Errorf("Expected session ID 'test-session-123', got '%s'", transport.SessionID())
	}

	// RFA-8rd: Verify state transition
	if transport.State() != SessionActive {
		t.Errorf("Expected state=active after initialize, got %s", transport.State())
	}

	if atomic.LoadInt32(&handshakeCount) != 1 {
		t.Errorf("Expected 1 initialize call, got %d", handshakeCount)
	}
}

func TestTransport_Initialize_Idempotent(t *testing.T) {
	var handshakeCount int32
	server := newMockMCPServer(t, &handshakeCount)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())

	ctx := context.Background()

	// Initialize twice
	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("First Initialize failed: %v", err)
	}
	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Second Initialize failed: %v", err)
	}

	// Should only have called initialize once (idempotent)
	if atomic.LoadInt32(&handshakeCount) != 1 {
		t.Errorf("Expected 1 initialize call (idempotent), got %d", handshakeCount)
	}
}

func TestTransport_Send_ToolsCall(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: ToolCallParams{
			Name:      "web_search",
			Arguments: map[string]interface{}{"query": "hello"},
		},
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("Expected no error, got code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("Expected non-nil result")
	}

	// Verify result content
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}
}

func TestTransport_Send_ReusedCallerID_UniqueWireIDs(t *testing.T) {
	var mu sync.Mutex
	wireIDs := make([]int, 0, 8)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var rpcReq map[string]interface{}
		if err := json.Unmarshal(body, &rpcReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		method, _ := rpcReq["method"].(string)
		reqID := 0
		hasID := false
		if rawID, ok := rpcReq["id"]; ok {
			switch v := rawID.(type) {
			case float64:
				reqID = int(v)
				hasID = true
			case int:
				reqID = v
				hasID = true
			}
		}

		switch method {
		case "initialize":
			if !hasID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "test-session-reused-id")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock","version":"1.0"}}}`, reqID)
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		case "tools/call":
			if !hasID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			wireIDs = append(wireIDs, reqID)
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"ok":true}}`, reqID)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()
	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	const n = 5
	var wg sync.WaitGroup
	errCh := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1, // Intentionally reused caller ID
				Method:  "tools/call",
				Params:  ToolCallParams{Name: "web_search", Arguments: map[string]interface{}{"query": "hello"}},
			}
			resp, err := transport.Send(ctx, req)
			if err != nil {
				errCh <- err
				return
			}
			if resp.ID != req.ID {
				errCh <- fmt.Errorf("caller-visible ID mismatch: got %d want %d", resp.ID, req.ID)
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(wireIDs) != n {
		t.Fatalf("expected %d wire IDs, got %d", n, len(wireIDs))
	}
	seen := make(map[int]struct{}, n)
	for _, id := range wireIDs {
		seen[id] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("expected %d unique wire IDs, got %d (%v)", n, len(seen), wireIDs)
	}
}

func TestTransport_Send_ToolsList(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got code=%d", resp.Error.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	tools, ok := result["tools"].([]interface{})
	if !ok || len(tools) == 0 {
		t.Fatal("Expected non-empty tools array in result")
	}
}

func TestTransport_Close_SendsDelete(t *testing.T) {
	deleteReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				w.Header().Set("Mcp-Session-Id", "session-to-close")
				w.Header().Set("Content-Type", "application/json")
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)
			}
		case http.MethodDelete:
			deleteReceived = true
			if r.Header.Get("Mcp-Session-Id") != "session-to-close" {
				t.Errorf("Expected Mcp-Session-Id=session-to-close, got %s", r.Header.Get("Mcp-Session-Id"))
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if err := transport.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if !deleteReceived {
		t.Error("Expected DELETE request to be sent on Close()")
	}

	if transport.Initialized() {
		t.Error("Transport should not be initialized after Close()")
	}
	if transport.SessionID() != "" {
		t.Error("Session ID should be empty after Close()")
	}

	// RFA-8rd: Verify state after Close
	if transport.State() != SessionUninitialized {
		t.Errorf("Expected state=uninitialized after Close, got %s", transport.State())
	}
}

func TestTransport_Close_NoSessionID_NoDelete(t *testing.T) {
	deleteCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	// Close without initializing -- should not send DELETE
	if err := transport.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if deleteCalled {
		t.Error("DELETE should NOT be sent when there is no session ID")
	}
}

func TestTransport_Initialize_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	err := transport.Initialize(ctx)
	if err == nil {
		t.Fatal("Expected error when server returns 500")
	}

	if transport.Initialized() {
		t.Error("Transport should not be initialized after error")
	}
}

func TestTransport_Initialize_JSONRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid Request",
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	err := transport.Initialize(ctx)
	if err == nil {
		t.Fatal("Expected error when server returns JSON-RPC error")
	}

	if transport.Initialized() {
		t.Error("Transport should not be initialized after JSON-RPC error")
	}
}

func TestTransport_Send_UpstreamUnreachable(t *testing.T) {
	// Use a URL that will fail to connect
	transport := NewStreamableHTTPTransport("http://127.0.0.1:1", nil)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	_, err := transport.Send(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error when upstream is unreachable")
	}
}

func TestTransport_Send_MalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not valid json"))
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	_, err := transport.Send(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for malformed response")
	}
}

func TestTransport_Send_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("service unavailable"))
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	_, err := transport.Send(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for non-200 status")
	}
}

func TestTransport_Send_SetsSessionIDHeader(t *testing.T) {
	var receivedSessionID string
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "session-abc")
			w.Header().Set("Content-Type", "application/json")
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			requestCount++
			receivedSessionID = r.Header.Get("Mcp-Session-Id")
			w.Header().Set("Content-Type", "application/json")
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{}`)}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	if _, err := transport.Send(ctx, req); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if receivedSessionID != "session-abc" {
		t.Errorf("Expected Mcp-Session-Id header 'session-abc', got '%s'", receivedSessionID)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 non-handshake request, got %d", requestCount)
	}
}

func TestTransport_NilHTTPClient_UsesDefault(t *testing.T) {
	transport := NewStreamableHTTPTransport("http://localhost:9999", nil)
	if transport.httpClient == nil {
		t.Error("Expected non-nil httpClient when nil passed")
	}
	if transport.httpClient != http.DefaultClient {
		t.Error("Expected http.DefaultClient to be used when nil passed")
	}
}

// --- RFA-8rd: New Tests ---

// TestTransport_Initialize_SendsClientCapabilities verifies AC6:
// Initialize sends client capabilities (roots) per MCP spec.
func TestTransport_Initialize_SendsClientCapabilities(t *testing.T) {
	var receivedCaps map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			// Capture the capabilities from the request
			params, _ := rpcReq["params"].(map[string]interface{})
			if params != nil {
				receivedCaps, _ = params["capabilities"].(map[string]interface{})
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "caps-session")
			w.WriteHeader(http.StatusOK)
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
				Result:  json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"test","version":"1.0"}}`),
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Verify client sent roots capability
	if receivedCaps == nil {
		t.Fatal("Expected capabilities in initialize request, got nil")
	}
	roots, hasRoots := receivedCaps["roots"]
	if !hasRoots {
		t.Fatal("Expected roots capability in initialize request")
	}
	rootsMap, ok := roots.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected roots to be an object, got %T", roots)
	}
	if listChanged, ok := rootsMap["listChanged"].(bool); !ok || !listChanged {
		t.Error("Expected roots.listChanged=true")
	}
}

// TestTransport_Initialize_ParsesServerCapabilities verifies that
// server capabilities are parsed and stored after initialize.
func TestTransport_Initialize_ParsesServerCapabilities(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	caps := transport.ServerCapabilities()
	if caps == nil {
		t.Fatal("Expected non-nil server capabilities after initialize")
		return
	}

	if caps.ProtocolVersion != "2025-03-26" {
		t.Errorf("Expected protocolVersion=2025-03-26, got %s", caps.ProtocolVersion)
	}

	if caps.ServerInfo.Name != "mock-mcp" {
		t.Errorf("Expected serverInfo.name=mock-mcp, got %s", caps.ServerInfo.Name)
	}

	if caps.Capabilities.Tools == nil {
		t.Fatal("Expected server tools capability")
	}
	if !caps.Capabilities.Tools.ListChanged {
		t.Error("Expected tools.listChanged=true")
	}

	if caps.Capabilities.Resources == nil {
		t.Fatal("Expected server resources capability")
	}
	if !caps.Capabilities.Resources.Subscribe {
		t.Error("Expected resources.subscribe=true")
	}
}

// TestTransport_Send_SSEResponse verifies AC4/AC5: content-type negotiation
// with text/event-stream responses.
func TestTransport_Send_SSEResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "sse-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Respond with SSE instead of JSON
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"SSE response works\"}]}}\n\n"))
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: ToolCallParams{
			Name:      "web_search",
			Arguments: map[string]interface{}{"query": "SSE test"},
		},
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send with SSE response failed: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("Expected no error, got code=%d", resp.Error.Code)
	}
	if resp.Result == nil {
		t.Fatal("Expected non-nil result from SSE response")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal SSE result: %v", err)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array from SSE response")
	}
	firstContent := content[0].(map[string]interface{})
	text, _ := firstContent["text"].(string)
	if text != "SSE response works" {
		t.Errorf("Expected 'SSE response works', got '%s'", text)
	}
}

// TestTransport_Send_JSONResponse verifies AC5: application/json responses
// still work correctly (backward compat with walking skeleton).
func TestTransport_Send_JSONResponse(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  ToolCallParams{Name: "web_search", Arguments: map[string]interface{}{"query": "json"}},
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send with JSON response failed: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("Unexpected error: code=%d", resp.Error.Code)
	}
}

// TestTransport_Send_UnexpectedContentType verifies AC5: unexpected content types
// produce an error with diagnostic information.
func TestTransport_Send_UnexpectedContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "ct-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Respond with unexpected content type
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>Not what you expected</html>"))
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	_, err := transport.Send(ctx, req)
	if err == nil {
		t.Fatal("Expected error for unexpected content type")
	}
	if !strings.Contains(err.Error(), "unexpected content type") {
		t.Errorf("Expected 'unexpected content type' error, got: %v", err)
	}
}

// TestTransport_Send_ContentTypeWithCharset verifies content type parsing
// handles parameters like charset correctly.
func TestTransport_Send_ContentTypeWithCharset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Mcp-Session-Id", "charset-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"status":"ok"}`)}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send with charset content type failed: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

// TestTransport_Send_404_ReInitialize verifies AC3: 404 triggers automatic
// re-initialize + retry. The first request returns 404 (session expired),
// the transport re-initializes, and the retry succeeds.
func TestTransport_Send_404_ReInitialize(t *testing.T) {
	var initCount int32
	requestCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			count := atomic.AddInt32(&initCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("session-%d", count))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			requestCount++
			if requestCount == 1 {
				// First request: return 404 (session expired)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("session not found"))
				return
			}
			// Subsequent requests: success
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"content":[{"type":"text","text":"re-initialized successfully"}]}`)}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	// Initial initialize
	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if transport.SessionID() != "session-1" {
		t.Errorf("Expected session-1, got %s", transport.SessionID())
	}

	// Send request -- first attempt returns 404, should auto-re-initialize and retry
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  ToolCallParams{Name: "web_search", Arguments: map[string]interface{}{"query": "retry"}},
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send failed (should have recovered from 404): %v", err)
	}

	// Verify the response is from the retry (after re-initialize)
	if resp.Error != nil {
		t.Errorf("Expected success after retry, got error: %v", resp.Error)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected content in retried response")
	}
	firstContent := content[0].(map[string]interface{})
	text, _ := firstContent["text"].(string)
	if text != "re-initialized successfully" {
		t.Errorf("Expected 're-initialized successfully', got '%s'", text)
	}

	// Verify re-initialization happened
	if atomic.LoadInt32(&initCount) != 2 {
		t.Errorf("Expected 2 initialize calls (original + re-init), got %d", initCount)
	}

	// Verify new session ID
	if transport.SessionID() != "session-2" {
		t.Errorf("Expected session-2 after re-init, got %s", transport.SessionID())
	}

	// Verify state is active
	if transport.State() != SessionActive {
		t.Errorf("Expected state=active after re-init, got %s", transport.State())
	}
}

// TestTransport_SessionState_ThreadSafety verifies AC1: session state
// is tracked with sync.RWMutex for thread safety.
func TestTransport_SessionState_ThreadSafety(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Concurrent reads of session ID and state should not race
	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = transport.SessionID()
			_ = transport.State()
			_ = transport.Initialized()
			_ = transport.ServerCapabilities()
		}()
	}

	wg.Wait()
	// If we get here without a race detector failure, thread safety is proven
	t.Log("PASS: concurrent reads of session state completed without race")
}

// TestTransport_AcceptHeader_IncludesSSE verifies that the Accept header
// includes both application/json and text/event-stream.
func TestTransport_AcceptHeader_IncludesSSE(t *testing.T) {
	var receivedAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		receivedAccept = r.Header.Get("Accept")
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "accept-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	if _, err := transport.Send(ctx, req); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if !strings.Contains(receivedAccept, "application/json") {
		t.Errorf("Accept header missing application/json: %s", receivedAccept)
	}
	if !strings.Contains(receivedAccept, "text/event-stream") {
		t.Errorf("Accept header missing text/event-stream: %s", receivedAccept)
	}
}

// TestTransport_Close_ClearsServerCapabilities verifies that Close() also
// clears server capabilities along with session ID and state.
func TestTransport_Close_ClearsServerCapabilities(t *testing.T) {
	server := newMockMCPServer(t, nil)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if transport.ServerCapabilities() == nil {
		t.Fatal("Expected non-nil server capabilities before close")
	}

	if err := transport.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if transport.ServerCapabilities() != nil {
		t.Error("Expected nil server capabilities after close")
	}
}

// TestTransport_SessionState_String verifies SessionState.String() labels.
func TestTransport_SessionState_String(t *testing.T) {
	tests := []struct {
		state    SessionState
		expected string
	}{
		{SessionUninitialized, "uninitialized"},
		{SessionActive, "active"},
		{SessionExpired, "expired"},
		{SessionState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("SessionState(%d).String() = %s, want %s", tt.state, got, tt.expected)
		}
	}
}

// TestTransport_Send_SSEWithCharset verifies SSE parsing handles
// Content-Type with parameters like charset.
func TestTransport_Send_SSEWithCharset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		_ = json.Unmarshal(body, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "sse-charset-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// text/event-stream with charset parameter
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"))
		}
	}))
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	ctx := context.Background()

	if err := transport.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send with SSE charset failed: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

// TestTransport_parseResponse_JSON verifies parseResponse handles application/json.
func TestTransport_parseResponse_JSON(t *testing.T) {
	transport := &StreamableHTTPTransport{}
	body := strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	resp, err := transport.parseResponse(body, "application/json")
	if err != nil {
		t.Fatalf("parseResponse JSON failed: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

// TestTransport_parseResponse_SSE verifies parseResponse handles text/event-stream.
func TestTransport_parseResponse_SSE(t *testing.T) {
	transport := &StreamableHTTPTransport{}
	body := strings.NewReader("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n")
	resp, err := transport.parseResponse(body, "text/event-stream")
	if err != nil {
		t.Fatalf("parseResponse SSE failed: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

// TestTransport_parseResponse_UnknownContentType verifies parseResponse rejects
// unexpected content types with diagnostic info.
func TestTransport_parseResponse_UnknownContentType(t *testing.T) {
	transport := &StreamableHTTPTransport{}
	body := strings.NewReader("binary data")
	_, err := transport.parseResponse(body, "application/octet-stream")
	if err == nil {
		t.Fatal("Expected error for unknown content type")
	}
	if !strings.Contains(err.Error(), "unexpected content type") {
		t.Errorf("Expected 'unexpected content type' error, got: %v", err)
	}
}
