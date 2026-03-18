package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// StreamableHTTPTransport implements MCP Streamable HTTP transport per spec 2025-03-26.
// It manages the MCP session lifecycle: initialize handshake, request/response,
// session expiry detection with auto-re-initialize, and session termination.
//
// RFA-9ol: Walking skeleton. RFA-8rd: Full session management, SSE parsing, lifecycle.
type StreamableHTTPTransport struct {
	baseURL    string
	httpClient *http.Client

	// mu protects sessionID, state, and serverCaps.
	// Uses RWMutex: reads (SessionID, State, ServerCapabilities) take RLock,
	// writes (Initialize, Close, session expiry reset) take full Lock.
	mu         sync.RWMutex
	sessionID  string            // Mcp-Session-Id from initialize response
	state      SessionState      // current session lifecycle state
	serverCaps *InitializeResult // parsed server capabilities from initialize
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
		state:      SessionUninitialized,
	}
}

// Initialize performs the 2-step MCP handshake:
//  1. POST {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}} -> capture Mcp-Session-Id
//  2. POST {"jsonrpc":"2.0","method":"notifications/initialized"} (notification, no id)
//
// Client capabilities (roots, sampling) are sent per MCP spec.
// Server capabilities are parsed from the initialize response and stored.
//
// This method is safe for concurrent use; only the first caller initializes.
func (t *StreamableHTTPTransport) Initialize(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state == SessionActive {
		return nil
	}

	// Step 1: Send initialize request with client capabilities.
	// NOTE: We pass the current sessionID (empty during first init) directly
	// to avoid re-acquiring the lock (sync.RWMutex is not reentrant).
	initReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: InitializeParams{
			ProtocolVersion: "2025-03-26",
			Capabilities: ClientCapabilities{
				Roots: &RootsCapability{ListChanged: true},
			},
			ClientInfo: ClientInfo{
				Name:    "precinct-gateway",
				Version: "1.0.0",
			},
		},
	}

	resp, err := t.doPostWithSID(ctx, initReq, t.sessionID)
	if err != nil {
		return fmt.Errorf("initialize request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("initialize returned status %d: %s", resp.StatusCode, string(body))
	}

	// Capture Mcp-Session-Id from response headers
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.sessionID = sid
	}

	// Parse the initialize response. The MCP spec allows servers to respond
	// with either application/json or text/event-stream for POST requests.
	// Use parseResponse for content-type negotiation (same as Send).
	contentType := resp.Header.Get("Content-Type")
	initResp, err := t.parseResponse(resp.Body, contentType)
	if err != nil {
		return fmt.Errorf("failed to parse initialize response: %w", err)
	}
	if initResp.Error != nil {
		return fmt.Errorf("initialize error: code=%d message=%s", initResp.Error.Code, initResp.Error.Message)
	}

	// Parse server capabilities from the result
	if initResp.Result != nil {
		var initResult InitializeResult
		if err := json.Unmarshal(initResp.Result, &initResult); err == nil {
			t.serverCaps = &initResult
		}
		// Non-fatal if parsing fails -- capabilities are optional for transport
	}

	// Step 2: Send notifications/initialized (notification -- no id field).
	// Use the newly acquired session ID from step 1.
	notif := &JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}

	notifResp, err := t.doPostNotificationWithSID(ctx, notif, t.sessionID)
	if err != nil {
		return fmt.Errorf("notifications/initialized failed: %w", err)
	}
	defer func() {
		_ = notifResp.Body.Close()
	}()
	// Notifications may return 200, 202, or 204; accept all.
	if notifResp.StatusCode != http.StatusOK && notifResp.StatusCode != http.StatusAccepted && notifResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(notifResp.Body)
		return fmt.Errorf("notifications/initialized returned status %d: %s", notifResp.StatusCode, string(body))
	}

	t.state = SessionActive
	return nil
}

// Send sends a JSON-RPC request and returns the response.
// Handles content-type negotiation:
//   - application/json -> direct JSON parse
//   - text/event-stream -> parse SSE events, extract JSON-RPC from data fields
//
// If the server returns 404 (session expired), the transport automatically
// re-initializes and retries the original request exactly once.
//
// The caller must have called Initialize() first (or rely on the gateway's
// lazy initialization logic).
func (t *StreamableHTTPTransport) Send(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
	wireReq := *req
	wireReq.ID = nextWireRequestID()

	resp, err := t.doPost(ctx, &wireReq)
	if err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// 404 = session expired. Re-initialize and retry once.
	if resp.StatusCode == http.StatusNotFound {
		// Drain the original response body before retrying.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if err := t.reInitialize(ctx); err != nil {
			return nil, fmt.Errorf("re-initialize after 404 failed: %w", err)
		}

		// Retry the original request with the new session
		resp, err = t.doPost(ctx, &wireReq)
		if err != nil {
			return nil, fmt.Errorf("retry after re-initialize failed: %w", err)
		}
		defer func() {
			_ = resp.Body.Close()
		}()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upstream returned status %d: %s", resp.StatusCode, string(body))
	}

	// Content-type negotiation: handle both JSON and SSE responses
	contentType := resp.Header.Get("Content-Type")
	rpcResp, err := t.parseResponse(resp.Body, contentType)
	if err != nil {
		return nil, err
	}
	// Preserve caller-visible ID semantics while using a unique wire ID.
	rpcResp.ID = req.ID
	return rpcResp, nil
}

// parseResponse parses the response body based on Content-Type.
//   - application/json -> direct JSON decode
//   - text/event-stream -> SSE parsing to extract JSON-RPC response
//   - anything else -> error (unexpected content type)
func (t *StreamableHTTPTransport) parseResponse(body io.Reader, contentType string) (*JSONRPCResponse, error) {
	// Normalize content type (strip parameters like charset)
	ct := strings.ToLower(contentType)
	ct = strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])

	switch ct {
	case "application/json":
		var rpcResp JSONRPCResponse
		if err := json.NewDecoder(body).Decode(&rpcResp); err != nil {
			return nil, fmt.Errorf("failed to parse JSON response: %w", err)
		}
		return &rpcResp, nil

	case "text/event-stream":
		return ParseSSEResponse(body)

	default:
		// Read a snippet for diagnostics
		snippet := make([]byte, 256)
		n, _ := body.Read(snippet)
		return nil, fmt.Errorf("unexpected content type %q from MCP server (body preview: %s)", contentType, string(snippet[:n]))
	}
}

// reInitialize clears the session state and performs a fresh initialize handshake.
// Called when the server returns 404 (session expired).
func (t *StreamableHTTPTransport) reInitialize(ctx context.Context) error {
	t.mu.Lock()
	t.sessionID = ""
	t.state = SessionExpired
	t.serverCaps = nil
	t.mu.Unlock()

	return t.Initialize(ctx)
}

// Close sends a DELETE to terminate the MCP session (if a session ID is set).
func (t *StreamableHTTPTransport) Close(ctx context.Context) error {
	t.mu.Lock()
	sid := t.sessionID
	t.state = SessionUninitialized
	t.sessionID = ""
	t.serverCaps = nil
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
	defer func() {
		_ = resp.Body.Close()
	}()

	return nil
}

// Initialized returns whether the transport has completed the MCP handshake.
func (t *StreamableHTTPTransport) Initialized() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state == SessionActive
}

// SessionID returns the current MCP session ID (empty if not yet initialized).
func (t *StreamableHTTPTransport) SessionID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessionID
}

// State returns the current session state.
func (t *StreamableHTTPTransport) State() SessionState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state
}

// ServerCapabilities returns the server's capabilities from the initialize response.
// Returns nil if not yet initialized or if the server did not provide capabilities.
func (t *StreamableHTTPTransport) ServerCapabilities() *InitializeResult {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.serverCaps
}

// doPost reads the session ID under RLock and sends a POST request.
// This is the public-facing version used by Send() and other callers
// that are NOT already holding the lock.
func (t *StreamableHTTPTransport) doPost(ctx context.Context, payload interface{}) (*http.Response, error) {
	t.mu.RLock()
	sid := t.sessionID
	t.mu.RUnlock()

	return t.doPostWithSID(ctx, payload, sid)
}

// doPostWithSID marshals the payload as JSON and POSTs it to baseURL with MCP headers.
// The session ID is passed explicitly so callers already holding the lock
// (e.g., Initialize) can avoid re-acquiring it (sync.RWMutex is not reentrant).
// Accept header includes both application/json and text/event-stream per MCP spec.
func (t *StreamableHTTPTransport) doPostWithSID(ctx context.Context, payload interface{}, sessionID string) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Accept both JSON and SSE per MCP Streamable HTTP spec
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	return t.httpClient.Do(req)
}

// doPostNotificationWithSID marshals a notification and POSTs it with an explicit
// session ID. Used by Initialize() which already holds the lock.
func (t *StreamableHTTPTransport) doPostNotificationWithSID(ctx context.Context, notif *JSONRPCNotification, sessionID string) (*http.Response, error) {
	body, err := json.Marshal(notif)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create notification request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	return t.httpClient.Do(req)
}
