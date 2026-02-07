package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// StreamableHTTPTransport implements MCP Streamable HTTP transport per spec 2025-03-26.
// It manages the MCP session lifecycle: initialize handshake, request/response,
// and session termination.
type StreamableHTTPTransport struct {
	baseURL    string
	httpClient *http.Client

	mu          sync.Mutex
	sessionID   string // Mcp-Session-Id from initialize response
	initialized bool
}

// NewStreamableHTTPTransport creates a transport for the given MCP server URL.
// The httpClient is used for all HTTP requests. If nil, http.DefaultClient is used.
func NewStreamableHTTPTransport(baseURL string, httpClient *http.Client) *StreamableHTTPTransport {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &StreamableHTTPTransport{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// Initialize performs the 2-step MCP handshake:
//  1. POST {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}} -> capture Mcp-Session-Id
//  2. POST {"jsonrpc":"2.0","method":"notifications/initialized"} (notification, no id)
//
// This method is safe for concurrent use; only the first caller initializes.
func (t *StreamableHTTPTransport) Initialize(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.initialized {
		return nil
	}

	// Step 1: Send initialize request
	initReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: InitializeParams{
			ProtocolVersion: "2025-03-26",
			Capabilities:    ClientCapabilities{},
			ClientInfo: ClientInfo{
				Name:    "mcp-security-gateway",
				Version: "1.0.0",
			},
		},
	}

	resp, err := t.doPost(ctx, initReq)
	if err != nil {
		return fmt.Errorf("initialize request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("initialize returned status %d: %s", resp.StatusCode, string(body))
	}

	// Capture Mcp-Session-Id from response headers
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.sessionID = sid
	}

	// Parse the initialize response to verify it is valid JSON-RPC
	var initResp JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&initResp); err != nil {
		return fmt.Errorf("failed to parse initialize response: %w", err)
	}
	if initResp.Error != nil {
		return fmt.Errorf("initialize error: code=%d message=%s", initResp.Error.Code, initResp.Error.Message)
	}

	// Step 2: Send notifications/initialized (notification -- no id field)
	notif := &JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	notifResp, err := t.doPostNotification(ctx, notif)
	if err != nil {
		return fmt.Errorf("notifications/initialized failed: %w", err)
	}
	defer notifResp.Body.Close()
	// Notifications may return 200 or 204; we accept both.
	if notifResp.StatusCode != http.StatusOK && notifResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(notifResp.Body)
		return fmt.Errorf("notifications/initialized returned status %d: %s", notifResp.StatusCode, string(body))
	}

	t.initialized = true
	return nil
}

// Send sends a JSON-RPC request and returns the response.
// Sets Content-Type: application/json and Mcp-Session-Id header (if available).
// The caller must have called Initialize() first (or rely on the gateway's
// lazy initialization logic).
func (t *StreamableHTTPTransport) Send(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
	resp, err := t.doPost(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upstream returned status %d: %s", resp.StatusCode, string(body))
	}

	var rpcResp JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &rpcResp, nil
}

// Close sends a DELETE to terminate the MCP session (if a session ID is set).
func (t *StreamableHTTPTransport) Close(ctx context.Context) error {
	t.mu.Lock()
	sid := t.sessionID
	t.initialized = false
	t.sessionID = ""
	t.mu.Unlock()

	if sid == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, t.baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request: %w", err)
	}
	req.Header.Set("Mcp-Session-Id", sid)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE request failed: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// Initialized returns whether the transport has completed the MCP handshake.
func (t *StreamableHTTPTransport) Initialized() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.initialized
}

// SessionID returns the current MCP session ID (empty if not yet initialized).
func (t *StreamableHTTPTransport) SessionID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessionID
}

// doPost marshals the payload as JSON and POSTs it to baseURL with MCP headers.
func (t *StreamableHTTPTransport) doPost(ctx context.Context, payload interface{}) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if t.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", t.sessionID)
	}

	return t.httpClient.Do(req)
}

// doPostNotification marshals a notification and POSTs it. Notifications have
// no id field so we use a separate type to avoid including "id":0 in the JSON.
func (t *StreamableHTTPTransport) doPostNotification(ctx context.Context, notif *JSONRPCNotification) (*http.Response, error) {
	body, err := json.Marshal(notif)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create notification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if t.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", t.sessionID)
	}

	return t.httpClient.Do(req)
}
