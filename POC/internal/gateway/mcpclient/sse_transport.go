// Legacy SSE transport for MCP servers using the deprecated SSE transport
// (pre-2025-03-26 MCP spec). This transport implements the Transport interface
// so the gateway can use it interchangeably with StreamableHTTPTransport.
//
// Protocol:
//  1. Client sends GET to /sse -- server responds with an SSE stream.
//  2. The first SSE event has type "endpoint" and its data field contains
//     the URL where JSON-RPC messages should be POSTed.
//  3. Client POSTs JSON-RPC requests to that URL.
//  4. Responses arrive on the SSE stream as "message" events, matched by
//     JSON-RPC ID.
//  5. A background goroutine reads the SSE stream and dispatches responses
//     to waiting callers via per-request channels.
//
// RFA-0dz: Legacy SSE transport + auto-detection.
package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultSSETimeout is the default timeout for waiting for a response on the
// SSE stream after sending a request. Individual Send calls can use a shorter
// timeout via context deadline.
const DefaultSSETimeout = 30 * time.Second

// LegacySSETransport implements the Transport interface for legacy MCP servers
// that use the deprecated SSE transport (pre-2025-03-26 MCP spec).
type LegacySSETransport struct {
	baseURL    string
	httpClient *http.Client

	// messageURL is the URL from the "endpoint" SSE event, where JSON-RPC
	// messages should be POSTed.
	messageURL string

	// sseResp holds the HTTP response for the long-lived SSE connection so we
	// can close it on shutdown.
	sseResp *http.Response

	// pending maps JSON-RPC request IDs to channels where the background
	// goroutine delivers the response.
	pending map[int]chan *JSONRPCResponse

	// mu protects messageURL, pending, and connected state.
	mu sync.Mutex

	// done signals the background goroutine to stop.
	done chan struct{}

	// connected tracks whether Connect() has been called successfully.
	connected bool
}

// NewLegacySSETransport creates a transport for a legacy SSE MCP server.
// The httpClient is used for all HTTP requests. If nil, http.DefaultClient is used.
func NewLegacySSETransport(baseURL string, httpClient *http.Client) *LegacySSETransport {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &LegacySSETransport{
		baseURL:    baseURL,
		httpClient: httpClient,
		pending:    make(map[int]chan *JSONRPCResponse),
		done:       make(chan struct{}),
	}
}

// ConnectWithTimeout establishes the SSE stream with a handshake timeout.
// The handshakeTimeout limits how long we wait for the initial HTTP response
// and the "endpoint" event. Once connected, the SSE stream body lives
// independently (not subject to the handshake timeout).
//
// CRITICAL: The HTTP request for the SSE stream must NOT use the timeout
// context, because cancelling a request context closes the response body.
// The SSE stream must survive after the handshake completes. Instead, we
// use the parent ctx for the HTTP request and a separate timer for the
// handshake deadline.
//
// RFA-xhr: Used by DetectTransportWithConfig to enforce per-probe timeouts
// on the Legacy SSE probe without hanging indefinitely on unresponsive servers.
func (t *LegacySSETransport) ConnectWithTimeout(ctx context.Context, handshakeTimeout time.Duration) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return nil
	}

	// Build the /sse URL
	sseURL, err := resolveSSEURL(t.baseURL)
	if err != nil {
		return fmt.Errorf("failed to resolve SSE URL: %w", err)
	}

	// CRITICAL: Use a background-derived context for the HTTP request so the
	// SSE stream body is NOT tied to the handshake timeout. The parent ctx
	// provides cancellation if the caller abandons detection entirely.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	// Start the HTTP request (this returns when headers are received)
	type dialResult struct {
		resp *http.Response
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		resp, dialErr := t.httpClient.Do(req)
		ch <- dialResult{resp, dialErr}
	}()

	// Wait for dial with timeout
	timer := time.NewTimer(handshakeTimeout)
	defer timer.Stop()

	var resp *http.Response
	select {
	case result := <-ch:
		if result.err != nil {
			return fmt.Errorf("SSE connection failed: %w", result.err)
		}
		resp = result.resp
	case <-timer.C:
		return fmt.Errorf("SSE handshake timed out after %v", handshakeTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return fmt.Errorf("SSE endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	t.sseResp = resp

	// Create a scanner on the response body
	scanner := bufio.NewScanner(resp.Body)

	// Read the endpoint event with a deadline. We use a goroutine + channel
	// to enforce the handshake timeout on the scanner read.
	type endpointResult struct {
		url string
		err error
	}
	epCh := make(chan endpointResult, 1)
	go func() {
		epURL, epErr := t.readEndpointEvent(ctx, scanner)
		epCh <- endpointResult{epURL, epErr}
	}()

	// Reset the timer for the endpoint event read
	timer.Reset(handshakeTimeout)
	var endpointURL string
	select {
	case result := <-epCh:
		if result.err != nil {
			_ = resp.Body.Close()
			return result.err
		}
		endpointURL = result.url
	case <-timer.C:
		_ = resp.Body.Close()
		return fmt.Errorf("SSE endpoint event timed out after %v", handshakeTimeout)
	case <-ctx.Done():
		_ = resp.Body.Close()
		return ctx.Err()
	}

	messageURL, err := resolveMessageURL(t.baseURL, endpointURL)
	if err != nil {
		_ = resp.Body.Close()
		return fmt.Errorf("invalid endpoint URL %q: %w", endpointURL, err)
	}
	t.messageURL = messageURL

	// Start background goroutine to read remaining SSE events (responses)
	go t.readSSELoop(scanner)

	t.connected = true
	return nil
}

// Connect establishes the SSE stream by sending GET /sse and waiting for the
// "endpoint" event that contains the URL for POSTing JSON-RPC messages.
// This must be called before Send(). It starts the background goroutine that
// reads the SSE stream and dispatches responses.
//
// The approach: we create a bufio.Scanner on the response body and read events
// until we find the "endpoint" event. Then we hand the SAME scanner to the
// background goroutine to continue reading "message" events (responses).
// This works because http.Response.Body is a stream -- the scanner picks up
// where Connect left off.
func (t *LegacySSETransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected {
		return nil
	}

	// Build the /sse URL
	sseURL, err := resolveSSEURL(t.baseURL)
	if err != nil {
		return fmt.Errorf("failed to resolve SSE URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return fmt.Errorf("SSE endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	t.sseResp = resp

	// Create a scanner on the response body. We read SSE events until we
	// find the "endpoint" event, then pass the scanner to the background
	// goroutine for ongoing response dispatch.
	scanner := bufio.NewScanner(resp.Body)

	// Read events until we find the "endpoint" event
	endpointURL, err := t.readEndpointEvent(ctx, scanner)
	if err != nil {
		_ = resp.Body.Close()
		return err
	}

	messageURL, err := resolveMessageURL(t.baseURL, endpointURL)
	if err != nil {
		_ = resp.Body.Close()
		return fmt.Errorf("invalid endpoint URL %q: %w", endpointURL, err)
	}
	t.messageURL = messageURL

	// Start background goroutine to read remaining SSE events (responses)
	// using the same scanner that is positioned after the endpoint event.
	go t.readSSELoop(scanner)

	t.connected = true
	return nil
}

// readEndpointEvent reads SSE events from the scanner until it finds an
// "endpoint" event and returns its data (the message URL). Returns an error
// if the stream ends without an endpoint event or the context is cancelled.
func (t *LegacySSETransport) readEndpointEvent(ctx context.Context, scanner *bufio.Scanner) (string, error) {
	var eventType string

	for scanner.Scan() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		line := scanner.Text()

		// Blank line = end of event
		if line == "" {
			eventType = ""
			continue
		}

		// Comment
		if strings.HasPrefix(line, ":") {
			continue
		}

		field, value := parseSSEField(line)
		switch field {
		case "event":
			eventType = value
		case "data":
			if eventType == "endpoint" {
				return value, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading SSE stream for endpoint: %w", err)
	}
	return "", fmt.Errorf("SSE stream ended without 'endpoint' event")
}

// Send sends a JSON-RPC request by POSTing to the message URL and waits for
// the response to arrive on the SSE stream, matched by request ID.
func (t *LegacySSETransport) Send(ctx context.Context, req *JSONRPCRequest) (*JSONRPCResponse, error) {
	t.mu.Lock()
	if !t.connected {
		t.mu.Unlock()
		return nil, fmt.Errorf("SSE transport not connected; call Connect() first")
	}

	// Register a channel for this request ID
	ch := make(chan *JSONRPCResponse, 1)
	t.pending[req.ID] = ch
	messageURL := t.messageURL
	t.mu.Unlock()

	// Clean up the pending entry when we're done
	defer func() {
		t.mu.Lock()
		delete(t.pending, req.ID)
		t.mu.Unlock()
	}()

	// POST the JSON-RPC request to the message URL
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, messageURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST to message URL failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// The server acknowledges the POST (200 or 202). The actual response
	// comes via the SSE stream.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("message POST returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Drain POST response body (may be empty for 202)
	_, _ = io.Copy(io.Discard, resp.Body)

	// Wait for the response on the SSE stream
	timeout := DefaultSSETimeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	select {
	case rpcResp := <-ch:
		if rpcResp == nil {
			return nil, fmt.Errorf("SSE transport closed while waiting for response")
		}
		return rpcResp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for SSE response for request ID %d", req.ID)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, fmt.Errorf("SSE transport closed while waiting for response")
	}
}

// Close terminates the SSE stream and cleans up the background goroutine.
func (t *LegacySSETransport) Close(_ context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected {
		return nil
	}

	// Signal the background goroutine to stop
	select {
	case <-t.done:
		// Already closed
	default:
		close(t.done)
	}

	// Close the SSE response body to unblock the scanner
	if t.sseResp != nil {
		_ = t.sseResp.Body.Close()
		t.sseResp = nil
	}

	t.connected = false
	t.messageURL = ""

	// Unblock any waiting senders by closing their channels
	for id, ch := range t.pending {
		close(ch)
		delete(t.pending, id)
	}

	return nil
}

// readSSELoop reads the SSE stream and dispatches responses to waiting callers.
// It runs in a background goroutine started by Connect(). The scanner is
// already positioned after the "endpoint" event.
func (t *LegacySSETransport) readSSELoop(scanner *bufio.Scanner) {
	var eventType string
	var dataLines []string

	for scanner.Scan() {
		// Check if we should stop
		select {
		case <-t.done:
			return
		default:
		}

		line := scanner.Text()

		// Blank line = end of event
		if line == "" {
			if len(dataLines) > 0 && (eventType == "message" || eventType == "") {
				data := strings.Join(dataLines, "\n")
				t.dispatchResponse(data)
			}
			eventType = ""
			dataLines = nil
			continue
		}

		// Comment
		if strings.HasPrefix(line, ":") {
			continue
		}

		field, value := parseSSEField(line)
		switch field {
		case "event":
			eventType = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}

	// Handle final event if stream ends without trailing blank line
	if len(dataLines) > 0 && (eventType == "message" || eventType == "") {
		data := strings.Join(dataLines, "\n")
		t.dispatchResponse(data)
	}
}

// dispatchResponse parses a JSON-RPC response from SSE data and delivers it
// to the waiting caller (if any) based on the request ID.
func (t *LegacySSETransport) dispatchResponse(data string) {
	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(data), &resp); err != nil {
		// Malformed response -- skip silently.
		return
	}

	t.mu.Lock()
	ch, exists := t.pending[resp.ID]
	t.mu.Unlock()

	if exists {
		// Non-blocking send -- if the channel is full (shouldn't happen with
		// buffer size 1), we drop the duplicate.
		select {
		case ch <- &resp:
		default:
		}
	}
}

// resolveSSEURL appends /sse to the base URL.
func resolveSSEURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/sse"
	return u.String(), nil
}

// resolveMessageURL resolves the message URL from the endpoint event data.
// The endpoint may be absolute or relative to the base URL.
func resolveMessageURL(baseURL, endpoint string) (string, error) {
	// If the endpoint is already an absolute URL, use it directly
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		_, err := url.Parse(endpoint)
		return endpoint, err
	}

	// Otherwise, resolve relative to the base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}
