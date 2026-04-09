// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- DetectConfig Tests ---

func TestDefaultDetectConfig(t *testing.T) {
	cfg := DefaultDetectConfig()
	if cfg.ProbeTimeout != 5*time.Second {
		t.Errorf("Expected ProbeTimeout=5s, got %v", cfg.ProbeTimeout)
	}
	if cfg.OverallTimeout != 15*time.Second {
		t.Errorf("Expected OverallTimeout=15s, got %v", cfg.OverallTimeout)
	}
}

// --- RetryConfig Tests ---

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()
	if cfg.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries=3, got %d", cfg.MaxRetries)
	}
	if cfg.InitialBackoff != 100*time.Millisecond {
		t.Errorf("Expected InitialBackoff=100ms, got %v", cfg.InitialBackoff)
	}
	if cfg.BackoffFactor != 2.0 {
		t.Errorf("Expected BackoffFactor=2.0, got %v", cfg.BackoffFactor)
	}
	if cfg.MaxBackoff != 2*time.Second {
		t.Errorf("Expected MaxBackoff=2s, got %v", cfg.MaxBackoff)
	}
}

func TestRetryConfig_BackoffDuration(t *testing.T) {
	cfg := RetryConfig{
		InitialBackoff: 100 * time.Millisecond,
		BackoffFactor:  2.0,
		MaxBackoff:     2 * time.Second,
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
		{4, 1600 * time.Millisecond},
		{5, 2 * time.Second}, // Capped at MaxBackoff
		{10, 2 * time.Second},
	}

	for _, tt := range tests {
		got := cfg.backoffDuration(tt.attempt)
		if got != tt.expected {
			t.Errorf("backoffDuration(%d) = %v, want %v", tt.attempt, got, tt.expected)
		}
	}
}

// --- ValidateResponse Tests ---

func TestValidateResponse_Valid_WithResult(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"ok":true}`)}

	if err := ValidateResponse(req, resp); err != nil {
		t.Errorf("Expected valid response, got error: %v", err)
	}
}

func TestValidateResponse_Valid_WithError(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Error:   &JSONRPCError{Code: -32601, Message: "Method not found"},
	}

	if err := ValidateResponse(req, resp); err != nil {
		t.Errorf("Expected valid error response, got validation error: %v", err)
	}
}

func TestValidateResponse_InvalidVersion(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{JSONRPC: "1.0", ID: 1, Result: json.RawMessage(`{}`)}

	err := ValidateResponse(req, resp)
	if err == nil {
		t.Fatal("Expected error for invalid version")
	}
	if !strings.Contains(err.Error(), "invalid jsonrpc version") {
		t.Errorf("Expected 'invalid jsonrpc version' error, got: %v", err)
	}
}

func TestValidateResponse_IDMismatch(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{JSONRPC: "2.0", ID: 2, Result: json.RawMessage(`{}`)}

	err := ValidateResponse(req, resp)
	if err == nil {
		t.Fatal("Expected error for ID mismatch")
	}
	if !strings.Contains(err.Error(), "ID mismatch") {
		t.Errorf("Expected 'ID mismatch' error, got: %v", err)
	}
}

func TestValidateResponse_BothResultAndError(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"ok":true}`),
		Error:   &JSONRPCError{Code: -32600, Message: "test"},
	}

	err := ValidateResponse(req, resp)
	if err == nil {
		t.Fatal("Expected error when both result and error present")
	}
	if !strings.Contains(err.Error(), "both result and error") {
		t.Errorf("Expected 'both result and error' error, got: %v", err)
	}
}

func TestValidateResponse_NeitherResultNorError(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{JSONRPC: "2.0", ID: 1}

	err := ValidateResponse(req, resp)
	if err == nil {
		t.Fatal("Expected error when neither result nor error present")
	}
	if !strings.Contains(err.Error(), "neither result nor error") {
		t.Errorf("Expected 'neither result nor error' error, got: %v", err)
	}
}

func TestValidateResponse_ErrorCodeZero(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      1,
		Error:   &JSONRPCError{Code: 0, Message: "invalid"},
	}

	err := ValidateResponse(req, resp)
	if err == nil {
		t.Fatal("Expected error for error code 0")
	}
	if !strings.Contains(err.Error(), "error code 0") {
		t.Errorf("Expected 'error code 0' error, got: %v", err)
	}
}

// --- LimitedReadResponse Tests ---

func TestLimitedReadResponse_WithinLimit(t *testing.T) {
	data := strings.Repeat("x", 100)
	result, err := LimitedReadResponse(strings.NewReader(data), 1024)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if string(result) != data {
		t.Errorf("Expected data to be unchanged")
	}
}

func TestLimitedReadResponse_ExceedsLimit(t *testing.T) {
	data := strings.Repeat("x", 2000)
	_, err := LimitedReadResponse(strings.NewReader(data), 1024)
	if err == nil {
		t.Fatal("Expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected 'exceeds maximum size' error, got: %v", err)
	}
}

func TestLimitedReadResponse_ExactlyAtLimit(t *testing.T) {
	data := strings.Repeat("x", 1024)
	result, err := LimitedReadResponse(strings.NewReader(data), 1024)
	if err != nil {
		t.Fatalf("Expected success at exact limit, got error: %v", err)
	}
	if len(result) != 1024 {
		t.Errorf("Expected 1024 bytes, got %d", len(result))
	}
}

// --- ParseLimitedJSONResponse Tests ---

func TestParseLimitedJSONResponse_Valid(t *testing.T) {
	respJSON := `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
	resp, err := ParseLimitedJSONResponse(strings.NewReader(respJSON), 1024)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

func TestParseLimitedJSONResponse_Oversized(t *testing.T) {
	// Generate a JSON response larger than the limit
	bigResult := strings.Repeat("a", 2000)
	respJSON := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"data":"%s"}}`, bigResult)
	_, err := ParseLimitedJSONResponse(strings.NewReader(respJSON), 1024)
	if err == nil {
		t.Fatal("Expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected 'exceeds maximum size' error, got: %v", err)
	}
}

func TestParseLimitedJSONResponse_MalformedJSON(t *testing.T) {
	_, err := ParseLimitedJSONResponse(strings.NewReader("not json"), 1024)
	if err == nil {
		t.Fatal("Expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "malformed JSON-RPC") {
		t.Errorf("Expected 'malformed JSON-RPC' error, got: %v", err)
	}
}

// --- isSessionLossError Tests ---

func TestIsSessionLossError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{nil, false},
		{fmt.Errorf("connection refused"), false},
		{fmt.Errorf("upstream returned status 404: session not found"), true},
		{fmt.Errorf("session expired"), true},
		{fmt.Errorf("SSE transport closed while waiting"), true},
		{fmt.Errorf("SSE stream disconnected"), true},
		{fmt.Errorf("timeout"), false}, // timeout is not session loss
		{fmt.Errorf("HTTP 500"), false},
	}

	for _, tt := range tests {
		got := isSessionLossError(tt.err)
		if got != tt.expected {
			errStr := "<nil>"
			if tt.err != nil {
				errStr = tt.err.Error()
			}
			t.Errorf("isSessionLossError(%q) = %v, want %v", errStr, got, tt.expected)
		}
	}
}

// --- SendWithRetry Tests ---

// mockRetryTransport allows controlling Send behavior per attempt.
type mockRetryTransport struct {
	sendFn func(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error)
}

func (m *mockRetryTransport) Send(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
	return m.sendFn(ctx, req)
}

func (m *mockRetryTransport) Close(_ context.Context) error {
	return nil
}

func TestSendWithRetry_SuccessOnFirstAttempt(t *testing.T) {
	transport := &mockRetryTransport{
		sendFn: func(_ context.Context, _ *JSONRPCRequest) (*JSONRPCResponse, error) {
			return &JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{}`)}, nil
		},
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	cfg := RetryConfig{MaxRetries: 3, InitialBackoff: 10 * time.Millisecond, BackoffFactor: 2.0, MaxBackoff: 100 * time.Millisecond}

	resp, err := SendWithRetry(context.Background(), transport, req, cfg, nil)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
}

func TestSendWithRetry_SessionLoss_RetrySucceeds(t *testing.T) {
	var attempt int32
	var reinitCount int32

	transport := &mockRetryTransport{
		sendFn: func(_ context.Context, _ *JSONRPCRequest) (*JSONRPCResponse, error) {
			n := atomic.AddInt32(&attempt, 1)
			if n == 1 {
				return nil, fmt.Errorf("upstream returned status 404: session not found")
			}
			return &JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"ok":true}`)}, nil
		},
	}

	reinitFn := func(_ context.Context) error {
		atomic.AddInt32(&reinitCount, 1)
		return nil
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	cfg := RetryConfig{MaxRetries: 3, InitialBackoff: 10 * time.Millisecond, BackoffFactor: 2.0, MaxBackoff: 100 * time.Millisecond}

	resp, err := SendWithRetry(context.Background(), transport, req, cfg, reinitFn)
	if err != nil {
		t.Fatalf("Expected success after retry, got error: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}

	if atomic.LoadInt32(&attempt) != 2 {
		t.Errorf("Expected 2 attempts (1 failure + 1 success), got %d", attempt)
	}
	if atomic.LoadInt32(&reinitCount) != 1 {
		t.Errorf("Expected 1 reinit call, got %d", reinitCount)
	}
}

func TestSendWithRetry_AllRetriesExhausted(t *testing.T) {
	transport := &mockRetryTransport{
		sendFn: func(_ context.Context, _ *JSONRPCRequest) (*JSONRPCResponse, error) {
			return nil, fmt.Errorf("upstream returned status 404: session expired")
		},
	}

	reinitFn := func(_ context.Context) error { return nil }

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	cfg := RetryConfig{MaxRetries: 2, InitialBackoff: 10 * time.Millisecond, BackoffFactor: 2.0, MaxBackoff: 100 * time.Millisecond}

	_, err := SendWithRetry(context.Background(), transport, req, cfg, reinitFn)
	if err == nil {
		t.Fatal("Expected error when all retries exhausted")
	}
	if !strings.Contains(err.Error(), "retries exhausted") {
		t.Errorf("Expected 'retries exhausted' error, got: %v", err)
	}
}

func TestSendWithRetry_NonRetryableError(t *testing.T) {
	var attempt int32
	transport := &mockRetryTransport{
		sendFn: func(_ context.Context, _ *JSONRPCRequest) (*JSONRPCResponse, error) {
			atomic.AddInt32(&attempt, 1)
			return nil, fmt.Errorf("connection refused") // Not a session loss error
		},
	}

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	cfg := RetryConfig{MaxRetries: 3, InitialBackoff: 10 * time.Millisecond, BackoffFactor: 2.0, MaxBackoff: 100 * time.Millisecond}

	_, err := SendWithRetry(context.Background(), transport, req, cfg, nil)
	if err == nil {
		t.Fatal("Expected error for non-retryable failure")
	}

	// Should NOT have retried -- only 1 attempt
	if atomic.LoadInt32(&attempt) != 1 {
		t.Errorf("Expected exactly 1 attempt (no retry for non-session-loss), got %d", attempt)
	}
}

func TestSendWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	transport := &mockRetryTransport{
		sendFn: func(_ context.Context, _ *JSONRPCRequest) (*JSONRPCResponse, error) {
			cancel() // Cancel context after first attempt
			return nil, fmt.Errorf("upstream returned status 404: session expired")
		},
	}

	reinitFn := func(_ context.Context) error { return nil }

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	cfg := RetryConfig{MaxRetries: 3, InitialBackoff: 10 * time.Millisecond, BackoffFactor: 2.0, MaxBackoff: 100 * time.Millisecond}

	_, err := SendWithRetry(ctx, transport, req, cfg, reinitFn)
	if err == nil {
		t.Fatal("Expected error on context cancellation")
	}
}

// --- Timeout Enforcement Tests ---

func TestDetectTransportWithConfig_ProbeTimeout(t *testing.T) {
	// Server that hangs on all requests -- should hit probe timeout
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done // Block until test releases
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	cfg := DetectConfig{
		ProbeTimeout:   150 * time.Millisecond,
		OverallTimeout: 500 * time.Millisecond,
	}

	start := time.Now()
	_, err := DetectTransportWithConfig(context.Background(), server.URL, server.Client(), cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected error when server hangs")
	}

	// Should complete within overall timeout (not hang forever)
	if elapsed > 2*time.Second {
		t.Errorf("Detection took too long (%v) -- should have timed out within %v", elapsed, cfg.OverallTimeout)
	}
}

func TestDetectTransportWithConfig_OverallTimeout(t *testing.T) {
	// Server that hangs -- overall timeout should fire
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	cfg := DetectConfig{
		ProbeTimeout:   200 * time.Millisecond,
		OverallTimeout: 300 * time.Millisecond,
	}

	start := time.Now()
	_, err := DetectTransportWithConfig(context.Background(), server.URL, server.Client(), cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected error on timeout")
	}

	// Should complete close to overall timeout
	if elapsed > 2*time.Second {
		t.Errorf("Detection took too long (%v)", elapsed)
	}
}

func TestDetectTransportWithConfig_StreamableHTTP_Success(t *testing.T) {
	// Healthy server that responds to Streamable HTTP
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "cfg-session")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"protocolVersion":"2025-03-26"}`)}
				_ = json.NewEncoder(w).Encode(resp)
			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	cfg := DetectConfig{
		ProbeTimeout:   2 * time.Second,
		OverallTimeout: 5 * time.Second,
	}

	transport, err := DetectTransportWithConfig(context.Background(), server.URL, server.Client(), cfg)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	_, ok := transport.(*StreamableHTTPTransport)
	if !ok {
		t.Errorf("Expected *StreamableHTTPTransport, got %T", transport)
	}
}

// --- ConnectWithTimeout Tests ---

func TestLegacySSETransport_ConnectWithTimeout_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/sse" {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()
			<-r.Context().Done()
		}
	}))
	defer server.Close()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := transport.ConnectWithTimeout(ctx, 2*time.Second); err != nil {
		t.Fatalf("ConnectWithTimeout failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	transport.mu.Lock()
	connected := transport.connected
	transport.mu.Unlock()

	if !connected {
		t.Error("Expected transport to be connected")
	}
}

func TestLegacySSETransport_ConnectWithTimeout_Timeout(t *testing.T) {
	// Server that hangs on the SSE endpoint
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	transport := NewLegacySSETransport(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := transport.ConnectWithTimeout(ctx, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Expected timeout error")
	}

	if elapsed > 2*time.Second {
		t.Errorf("ConnectWithTimeout took too long (%v) -- should have timed out", elapsed)
	}
}

// --- Request Timeout via Send Tests ---

func TestStreamableHTTP_Send_RequestTimeout(t *testing.T) {
	// Server that hangs on the actual request (not initialize)
	done := make(chan struct{})
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
			w.Header().Set("Mcp-Session-Id", "timeout-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			<-done // Hang on actual requests
		}
	}))
	defer func() {
		close(done)
		server.Close()
	}()

	transport := NewStreamableHTTPTransport(server.URL, server.Client())
	if err := transport.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Send with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := &JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call"}
	_, err := transport.Send(ctx, req)
	if err == nil {
		t.Fatal("Expected timeout error")
	}
}

// --- Upstream Drops Mid-Stream Tests ---

func TestStreamableHTTP_Send_UpstreamDropsMidStream(t *testing.T) {
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
			w.Header().Set("Mcp-Session-Id", "drop-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Write partial JSON then close connection (simulates mid-stream drop)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"resu`))
			// Hijack the connection to force close
			if hijacker, ok := w.(http.Hijacker); ok {
				conn, _, _ := hijacker.Hijack()
				if conn != nil {
					_ = conn.Close()
				}
			}
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
		t.Fatal("Expected error when upstream drops mid-stream")
	}
}

// --- Malformed JSON-RPC Response Test ---

func TestStreamableHTTP_Send_MalformedJSONRPC(t *testing.T) {
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
			w.Header().Set("Mcp-Session-Id", "malformed-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Return syntactically valid JSON but semantically wrong (non-JSON-RPC)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"not":"jsonrpc","format":"wrong"}`))
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
		// Error at transport level is acceptable (malformed)
		return
	}

	// If we got a response, validation should catch it
	if validErr := ValidateResponse(req, resp); validErr == nil {
		t.Error("Expected ValidateResponse to catch malformed response")
	}
}

// --- Non-JSON-RPC Response (HTML error page) ---

func TestStreamableHTTP_Send_NonJSONResponse(t *testing.T) {
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
			w.Header().Set("Mcp-Session-Id", "html-session")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// Return HTML error page instead of JSON-RPC
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>502 Bad Gateway</h1></body></html>`))
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
		t.Fatal("Expected error for HTML response")
	}
	if !strings.Contains(err.Error(), "unexpected content type") {
		t.Errorf("Expected 'unexpected content type' error, got: %v", err)
	}
}

// --- Session Expiry 404 During tools/call ---

func TestStreamableHTTP_Send_SessionExpiry404(t *testing.T) {
	var initCount int32

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
			n := atomic.AddInt32(&initCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", fmt.Sprintf("session-%d", n))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusOK)
		default:
			// First non-init request gets 404, subsequent get success.
			// The transport's built-in 404 handler will reinit and retry.
			sid := r.Header.Get("Mcp-Session-Id")
			if sid == "session-1" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("session not found"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{"ok":true}`)}
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
		t.Fatalf("Expected recovery from 404, got error: %v", err)
	}

	if resp.Result == nil {
		t.Fatal("Expected non-nil result after session recovery")
	}

	// Verify re-initialization happened
	if atomic.LoadInt32(&initCount) < 2 {
		t.Errorf("Expected at least 2 init calls, got %d", initCount)
	}
}

// --- Response Size Limit via ParseLimitedJSONResponse ---

func TestParseLimitedJSONResponse_OversizedResponse(t *testing.T) {
	// Create a response body larger than the limit
	largeData := bytes.Repeat([]byte("x"), 5000)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"data":"%s"}}`, string(largeData))

	_, err := ParseLimitedJSONResponse(strings.NewReader(body), 1024)
	if err == nil {
		t.Fatal("Expected error for oversized response body")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}
