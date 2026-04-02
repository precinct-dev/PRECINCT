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
	"testing"
	"time"
)

// newMockLegacySSEServer creates an httptest server that simulates a legacy SSE
// MCP server. On GET /sse, it sends an "endpoint" event followed by response
// events for any JSON-RPC requests POSTed to /message.
//
// The server processes requests synchronously: POST /message stores the request,
// and the SSE stream sends back the response.
func newMockLegacySSEServer(t *testing.T) *httptest.Server {
	t.Helper()

	type sseClient struct {
		events chan string
	}

	// mu protects registered SSE clients.
	var mu sync.Mutex
	var sseClients []*sseClient

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			// SSE endpoint: send the endpoint event, then keep the connection
			// open for response events.
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming not supported", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)

			client := &sseClient{events: make(chan string, 8)}
			mu.Lock()
			sseClients = append(sseClients, client)
			mu.Unlock()
			defer func() {
				mu.Lock()
				defer mu.Unlock()
				for i, existing := range sseClients {
					if existing == client {
						sseClients = append(sseClients[:i], sseClients[i+1:]...)
						break
					}
				}
			}()

			// Send the endpoint event with the message URL.
			// The URL uses the server's own address.
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()

			for {
				select {
				case <-r.Context().Done():
					return
				case event := <-client.events:
					_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", event)
					flusher.Flush()
				}
			}

		case r.Method == http.MethodPost && r.URL.Path == "/message":
			// Message endpoint: receive JSON-RPC request, send response via SSE
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var rpcReq JSONRPCRequest
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			// Build the response
			var result json.RawMessage
			switch rpcReq.Method {
			case "tools/call":
				result = json.RawMessage(`{"content":[{"type":"text","text":"SSE transport works"}]}`)
			case "tools/list":
				result = json.RawMessage(`{"tools":[{"name":"test_tool","description":"A test tool"}]}`)
			default:
				result = json.RawMessage(`{"status":"ok"}`)
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Result:  result,
			}

			respJSON, _ := json.Marshal(resp)

			// Acknowledge the POST
			w.WriteHeader(http.StatusAccepted)

			// Fan the response out to all active SSE streams. Each stream writes
			// from its own handler goroutine, avoiding concurrent ResponseWriter use.
			mu.Lock()
			clients := append([]*sseClient(nil), sseClients...)
			mu.Unlock()

			for _, client := range clients {
				timer := time.NewTimer(2 * time.Second)
				select {
				case client.events <- string(respJSON):
					if !timer.Stop() {
						<-timer.C
					}
				case <-timer.C:
					t.Errorf("timed out delivering mock SSE response for %s", rpcReq.Method)
				}
			}

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))

	t.Cleanup(server.Close)
	return server
}

// --- LegacySSETransport.Connect() Tests ---

func TestLegacySSETransport_Connect_ReceivesEndpoint(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Verify the message URL was set
	transport.mu.Lock()
	messageURL := transport.messageURL
	transport.mu.Unlock()

	if messageURL == "" {
		t.Fatal("Expected non-empty messageURL after Connect")
	}

	if !strings.Contains(messageURL, "/message") {
		t.Errorf("Expected messageURL to contain '/message', got %s", messageURL)
	}
}

func TestLegacySSETransport_Connect_Idempotent(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("First Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Second connect should be no-op
	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Second Connect failed: %v", err)
	}
}

func TestLegacySSETransport_Connect_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	err := transport.Connect(ctx)
	if err == nil {
		t.Fatal("Expected error when server returns 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected 500 in error, got: %v", err)
	}
}

func TestLegacySSETransport_Connect_NoEndpointEvent(t *testing.T) {
	// Server sends SSE but never the endpoint event
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Send a non-endpoint event, then close the connection
		_, _ = fmt.Fprintf(w, "event: ping\ndata: keep-alive\n\n")
		flusher.Flush()
		// Close without sending endpoint
	}))
	defer server.Close()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	err := transport.Connect(ctx)
	if err == nil {
		t.Fatal("Expected error when no endpoint event is sent")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("Expected 'endpoint' in error, got: %v", err)
	}
}

// --- LegacySSETransport.Send() Tests ---

func TestLegacySSETransport_Send_ToolsCall(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  ToolCallParams{Name: "web_search", Arguments: map[string]interface{}{"query": "test"}},
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("Expected id=1, got %d", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("Expected no error, got code=%d", resp.Error.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected non-empty content array in result")
	}
}

func TestLegacySSETransport_Send_ToolsList(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	resp, err := transport.Send(ctx, req)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if resp.ID != 2 {
		t.Errorf("Expected id=2, got %d", resp.ID)
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

func TestLegacySSETransport_Send_NotConnected(t *testing.T) {
	transport := NewLegacySSETransport("http://localhost:1", nil)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	_, err := transport.Send(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error when not connected")
	}
	if !strings.Contains(err.Error(), "not connected") {
		t.Errorf("Expected 'not connected' error, got: %v", err)
	}
}

func TestLegacySSETransport_Send_Timeout(t *testing.T) {
	// Server accepts SSE and POST but never sends a response via SSE
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()
			<-r.Context().Done()
		case r.Method == http.MethodPost && r.URL.Path == "/message":
			// Accept but never respond via SSE
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer server.Close()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Use a very short context deadline to trigger timeout quickly
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer sendCancel()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
	}

	_, err := transport.Send(sendCtx, req)
	if err == nil {
		t.Fatal("Expected timeout error")
	}
	// Should be either a context deadline exceeded or our timeout message
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("Expected timeout/deadline error, got: %v", err)
	}
}

// --- LegacySSETransport.Close() Tests ---

func TestLegacySSETransport_Close_TerminatesStream(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if err := transport.Close(context.Background()); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	transport.mu.Lock()
	connected := transport.connected
	messageURL := transport.messageURL
	transport.mu.Unlock()

	if connected {
		t.Error("Expected connected=false after Close")
	}
	if messageURL != "" {
		t.Error("Expected empty messageURL after Close")
	}
}

func TestLegacySSETransport_Close_NotConnected_NoError(t *testing.T) {
	transport := NewLegacySSETransport("http://localhost:1", nil)

	if err := transport.Close(context.Background()); err != nil {
		t.Fatalf("Close on unconnected transport should not error: %v", err)
	}
}

func TestLegacySSETransport_Close_Idempotent(t *testing.T) {
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if err := transport.Close(context.Background()); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}
	if err := transport.Close(context.Background()); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
}

// --- Background goroutine dispatch Tests ---

func TestLegacySSETransport_DispatchByID(t *testing.T) {
	// Verify that responses are dispatched to the correct caller by JSON-RPC ID
	server := newMockLegacySSEServer(t)

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Send two requests with different IDs
	req1 := &JSONRPCRequest{JSONRPC: "2.0", ID: 10, Method: "tools/call",
		Params: ToolCallParams{Name: "test", Arguments: map[string]interface{}{"q": "one"}}}
	req2 := &JSONRPCRequest{JSONRPC: "2.0", ID: 20, Method: "tools/list"}

	// Send sequentially and verify each gets the right response ID
	resp1, err := transport.Send(ctx, req1)
	if err != nil {
		t.Fatalf("Send req1 failed: %v", err)
	}
	if resp1.ID != 10 {
		t.Errorf("Expected resp1.ID=10, got %d", resp1.ID)
	}

	resp2, err := transport.Send(ctx, req2)
	if err != nil {
		t.Fatalf("Send req2 failed: %v", err)
	}
	if resp2.ID != 20 {
		t.Errorf("Expected resp2.ID=20, got %d", resp2.ID)
	}
}

func TestLegacySSETransport_ReusedCallerID_UniqueWireIDs(t *testing.T) {
	var mu sync.Mutex
	var sseWriter http.ResponseWriter
	var sseFlusher http.Flusher
	wireIDs := make([]int, 0, 8)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming not supported", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()

			mu.Lock()
			sseWriter = w
			sseFlusher = flusher
			mu.Unlock()

			<-r.Context().Done()

		case r.Method == http.MethodPost && r.URL.Path == "/message":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var rpcReq JSONRPCRequest
			if err := json.Unmarshal(body, &rpcReq); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}

			token := ""
			if params, ok := rpcReq.Params.(map[string]interface{}); ok {
				if v, ok := params["token"].(string); ok {
					token = v
				}
			}

			mu.Lock()
			wireIDs = append(wireIDs, rpcReq.ID)
			if sseWriter != nil {
				resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"token":"%s"}}`, rpcReq.ID, token)
				_, _ = fmt.Fprintf(sseWriter, "event: message\ndata: %s\n\n", resp)
				sseFlusher.Flush()
			}
			mu.Unlock()

			w.WriteHeader(http.StatusAccepted)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := transport.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer func() { _ = transport.Close(context.Background()) }()

	const n = 5
	var wg sync.WaitGroup
	errCh := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      1, // Intentionally reused caller ID
				Method:  "tools/call",
				Params: map[string]interface{}{
					"token": fmt.Sprintf("req-%d", idx),
				},
			}
			resp, err := transport.Send(ctx, req)
			if err != nil {
				errCh <- fmt.Errorf("send %d failed: %w", idx, err)
				return
			}
			if resp.ID != req.ID {
				errCh <- fmt.Errorf("send %d returned caller ID mismatch: got %d want %d", idx, resp.ID, req.ID)
				return
			}
		}(i)
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

// --- Transport interface compliance ---

func TestLegacySSETransport_ImplementsTransport(t *testing.T) {
	var _ Transport = (*LegacySSETransport)(nil)
}

func TestStreamableHTTPTransport_ImplementsTransport(t *testing.T) {
	var _ Transport = (*StreamableHTTPTransport)(nil)
}

// --- resolveSSEURL Tests ---

func TestResolveSSEURL(t *testing.T) {
	tests := []struct {
		baseURL  string
		expected string
	}{
		{"http://localhost:8080", "http://localhost:8080/sse"},
		{"http://localhost:8080/", "http://localhost:8080/sse"},
		{"http://localhost:8080/api", "http://localhost:8080/api/sse"},
		{"http://localhost:8080/api/", "http://localhost:8080/api/sse"},
	}

	for _, tt := range tests {
		got, err := resolveSSEURL(tt.baseURL)
		if err != nil {
			t.Errorf("resolveSSEURL(%q) error: %v", tt.baseURL, err)
			continue
		}
		if got != tt.expected {
			t.Errorf("resolveSSEURL(%q) = %q, want %q", tt.baseURL, got, tt.expected)
		}
	}
}

// --- resolveMessageURL Tests ---

func TestResolveMessageURL_Absolute(t *testing.T) {
	url, err := resolveMessageURL("http://localhost:8080", "http://example.com:9090/msg")
	if err != nil {
		t.Fatalf("resolveMessageURL error: %v", err)
	}
	if url != "http://example.com:9090/msg" {
		t.Errorf("Expected absolute URL unchanged, got %s", url)
	}
}

func TestResolveMessageURL_Relative(t *testing.T) {
	url, err := resolveMessageURL("http://localhost:8080", "/message")
	if err != nil {
		t.Fatalf("resolveMessageURL error: %v", err)
	}
	if url != "http://localhost:8080/message" {
		t.Errorf("Expected http://localhost:8080/message, got %s", url)
	}
}

// --- NilHTTPClient Test ---

func TestLegacySSETransport_NilHTTPClient_UsesDefault(t *testing.T) {
	transport := NewLegacySSETransport("http://localhost:9999", nil)
	if transport.httpClient == nil {
		t.Error("Expected non-nil httpClient when nil passed")
	}
	if transport.httpClient != http.DefaultClient {
		t.Error("Expected http.DefaultClient to be used when nil passed")
	}
}
