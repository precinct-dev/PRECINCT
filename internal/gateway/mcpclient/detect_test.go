package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- DetectTransport Tests ---

// TestDetectTransport_StreamableHTTP verifies that DetectTransport returns a
// StreamableHTTPTransport when the server supports Streamable HTTP.
func TestDetectTransport_StreamableHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "detect-session")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{}`)}
				_ = json.NewEncoder(w).Encode(resp)
			}
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport, err := DetectTransport(ctx, server.URL, server.Client())
	if err != nil {
		t.Fatalf("DetectTransport failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Verify it's a StreamableHTTPTransport
	_, ok := transport.(*StreamableHTTPTransport)
	if !ok {
		t.Errorf("Expected *StreamableHTTPTransport, got %T", transport)
	}
}

// TestDetectTransport_LegacySSE verifies that DetectTransport falls back to
// LegacySSETransport when the server does not support Streamable HTTP but
// does support Legacy SSE.
func TestDetectTransport_LegacySSE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/sse":
			// Legacy SSE endpoint
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
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost:
			// Reject Streamable HTTP initialize with 405
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport, err := DetectTransport(ctx, server.URL, server.Client())
	if err != nil {
		t.Fatalf("DetectTransport failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Verify it's a LegacySSETransport
	_, ok := transport.(*LegacySSETransport)
	if !ok {
		t.Errorf("Expected *LegacySSETransport, got %T", transport)
	}
}

// TestDetectTransport_NeitherWorks verifies that DetectTransport returns an error
// when neither Streamable HTTP nor Legacy SSE work.
func TestDetectTransport_NeitherWorks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject everything
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := DetectTransport(ctx, server.URL, server.Client())
	if err == nil {
		t.Fatal("Expected error when neither transport works")
	}
	if !containsAll(err.Error(), "failed to detect", "streamable HTTP", "legacy SSE") {
		t.Errorf("Expected error mentioning both transports, got: %v", err)
	}
}

// TestDetectTransport_PreferStreamableHTTP verifies that when BOTH transports
// would work, Streamable HTTP is preferred.
func TestDetectTransport_PreferStreamableHTTP(t *testing.T) {
	// Server supports both: POST for Streamable HTTP AND GET /sse for Legacy SSE
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "dual-session")
				w.WriteHeader(http.StatusOK)
				resp := JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      1,
					Result:  json.RawMessage(`{"protocolVersion":"2025-03-26"}`),
				}
				_ = json.NewEncoder(w).Encode(resp)
			case "notifications/initialized":
				w.WriteHeader(http.StatusOK)
			}
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
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transport, err := DetectTransport(ctx, server.URL, server.Client())
	if err != nil {
		t.Fatalf("DetectTransport failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()

	// Streamable HTTP should be preferred
	_, ok := transport.(*StreamableHTTPTransport)
	if !ok {
		t.Errorf("Expected *StreamableHTTPTransport (preferred), got %T", transport)
	}
}

// TestDetectTransport_NilHTTPClient verifies nil httpClient works.
func TestDetectTransport_NilHTTPClient(t *testing.T) {
	// Use a server that accepts Streamable HTTP
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var rpcReq map[string]interface{}
			_ = json.Unmarshal(body, &rpcReq)
			method, _ := rpcReq["method"].(string)

			switch method {
			case "initialize":
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Mcp-Session-Id", "nil-client-session")
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pass nil client - should use http.DefaultClient
	transport, err := DetectTransport(ctx, server.URL, nil)
	if err != nil {
		t.Fatalf("DetectTransport with nil client failed: %v", err)
	}
	defer func() {
		_ = transport.Close(context.Background())
	}()
}

// containsAll checks if s contains all the given substrings.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
