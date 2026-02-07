package mcpclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "test-session-123")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock-mcp","version":"1.0"}}`),
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

func TestTransport_Initialize_TwoStepHandshake(t *testing.T) {
	var handshakeCount int32
	server := newMockMCPServer(t, &handshakeCount)
	defer server.Close()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())

	if transport.Initialized() {
		t.Error("Transport should not be initialized before Initialize()")
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
