package mcpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Default configuration values for the client.
const (
	DefaultMaxRetries  = 3
	DefaultBackoffBase = 1 * time.Second
	DefaultTimeout     = 30 * time.Second
)

// Option configures a GatewayClient. Use the With* functions to create Options.
type Option func(*GatewayClient)

// WithSessionID sets the session ID. If not provided, a UUID is auto-generated.
func WithSessionID(id string) Option {
	return func(c *GatewayClient) { c.sessionID = id }
}

// WithTimeout sets the HTTP request timeout. Default is 30 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *GatewayClient) { c.timeout = d }
}

// WithMaxRetries sets the maximum retry attempts for 503 responses. Default is 3.
func WithMaxRetries(n int) Option {
	return func(c *GatewayClient) { c.maxRetries = n }
}

// WithBackoffBase sets the base duration for exponential backoff. Default is 1 second.
// Retry delays are: base, base*2, base*4, ...
func WithBackoffBase(d time.Duration) Option {
	return func(c *GatewayClient) { c.backoffBase = d }
}

// WithHTTPClient sets a custom *http.Client. This is useful for testing or
// when the caller needs custom TLS configuration (e.g., mTLS via go-spiffe).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *GatewayClient) { c.httpClient = hc }
}

// sleepFunc is the function used for backoff delays. Overridable for testing.
type sleepFunc func(time.Duration)

// withSleepFunc is an internal option for injecting a mock sleep in tests.
func withSleepFunc(fn sleepFunc) Option {
	return func(c *GatewayClient) { c.sleep = fn }
}

// GatewayClient is an HTTP client for MCP JSON-RPC calls through the
// security gateway. It handles envelope construction, required headers,
// error parsing, retry logic, and session management.
//
// Create with [NewClient]:
//
//	client := mcpgateway.NewClient("http://localhost:9090", "spiffe://poc.local/agents/example/dev")
//	result, err := client.Call(ctx, "tavily_search", map[string]any{"query": "AI security"})
type GatewayClient struct {
	url         string
	spiffeID    string
	sessionID   string
	timeout     time.Duration
	maxRetries  int
	backoffBase time.Duration
	httpClient  *http.Client
	sleep       sleepFunc
	requestID   atomic.Int64
}

// ModelChatRequest captures gateway-model-plane call options for OpenAI-compatible
// chat completions routing through PRECINCT Gateway model egress.
type ModelChatRequest struct {
	Model         string
	Messages      []map[string]any
	Provider      string
	APIKeyRef     string
	APIKeyHeader  string
	Endpoint      string
	Residency     string
	BudgetProfile string
	ExtraHeaders  map[string]string
	ExtraPayload  map[string]any
}

// NewClient creates a GatewayClient for the given gateway URL and SPIFFE identity.
//
// The url is the gateway base URL (e.g. "http://localhost:9090").
// The spiffeID is sent in the X-SPIFFE-ID header for authentication.
//
// Options customize timeout, retries, session ID, and HTTP client.
// If no session ID is provided, one is auto-generated.
func NewClient(url, spiffeID string, opts ...Option) *GatewayClient {
	c := &GatewayClient{
		url:         url,
		spiffeID:    spiffeID,
		sessionID:   uuid.New().String(),
		timeout:     DefaultTimeout,
		maxRetries:  DefaultMaxRetries,
		backoffBase: DefaultBackoffBase,
		sleep:       time.Sleep,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: c.timeout}
	}
	return c
}

// SessionID returns the session ID used by this client.
func (c *GatewayClient) SessionID() string {
	return c.sessionID
}

// CallModelChat sends an OpenAI-compatible chat completion request through the
// gateway model egress endpoint (default: /openai/v1/chat/completions).
func (c *GatewayClient) CallModelChat(ctx context.Context, req ModelChatRequest) (map[string]any, error) {
	endpoint := strings.TrimSpace(req.Endpoint)
	if endpoint == "" {
		endpoint = "/openai/v1/chat/completions"
	}
	targetURL := endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		if strings.HasPrefix(endpoint, "/") {
			targetURL = c.url + endpoint
		} else {
			targetURL = c.url + "/" + endpoint
		}
	}

	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		provider = "groq"
	}
	residency := strings.TrimSpace(req.Residency)
	if residency == "" {
		residency = "us"
	}
	budgetProfile := strings.TrimSpace(req.BudgetProfile)
	if budgetProfile == "" {
		budgetProfile = "standard"
	}

	payload := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
	}
	for k, v := range req.ExtraPayload {
		payload[k] = v
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to marshal model request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to create model request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-SPIFFE-ID", c.spiffeID)
	httpReq.Header.Set("X-Session-ID", c.sessionID)
	httpReq.Header.Set("X-Model-Provider", provider)
	httpReq.Header.Set("X-Residency-Intent", residency)
	httpReq.Header.Set("X-Budget-Profile", budgetProfile)

	apiKeyHeader := strings.TrimSpace(req.APIKeyHeader)
	if apiKeyHeader == "" {
		apiKeyHeader = "Authorization"
	}
	if strings.TrimSpace(req.APIKeyRef) != "" {
		httpReq.Header.Set(apiKeyHeader, req.APIKeyRef)
	}
	for k, v := range req.ExtraHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: model request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to read model response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, parseGatewayError(resp.StatusCode, respBody)
	}

	out := make(map[string]any)
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, &GatewayError{
			Code:       "invalid_response",
			Message:    fmt.Sprintf("invalid JSON response (HTTP %d): %s", resp.StatusCode, truncate(string(respBody), 200)),
			HTTPStatus: resp.StatusCode,
		}
	}
	return out, nil
}

// jsonRPCRequest is the MCP JSON-RPC request envelope.
type jsonRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      int64          `json:"id"`
}

// jsonRPCResponse is the MCP JSON-RPC response envelope.
type jsonRPCResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	Result  any            `json:"result,omitempty"`
	Error   map[string]any `json:"error,omitempty"`
	ID      any            `json:"id"`
}

// Call invokes a tool through the gateway using MCP-spec JSON-RPC.
//
// Primary path (spec):
//   - method="tools/call"
//   - params.name=<tool name>
//   - params.arguments=<tool arguments>
//
// Backward/advanced path:
// If methodOrTool looks like a JSON-RPC "protocol method" (e.g. "tools/list",
// "resources/read", "notifications/initialized", "initialize"), Call will send
// it as-is (method=<methodOrTool>, params=<params>).
//
// On success, the JSON-RPC "result" field is returned as a map.
// On denial or error, a *[GatewayError] is returned. Use [errors.As] to inspect it.
//
// Call respects context cancellation and deadline. It retries 503 responses
// with exponential backoff up to MaxRetries times.
func (c *GatewayClient) Call(ctx context.Context, methodOrTool string, params map[string]any) (any, error) {
	var lastErr *GatewayError

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		result, err := c.doCall(ctx, methodOrTool, params)
		if err == nil {
			return result, nil
		}

		ge, ok := err.(*GatewayError)
		if !ok {
			// Non-GatewayError (network issue, context cancelled, etc.) -- no retry
			return nil, err
		}

		if ge.HTTPStatus != http.StatusServiceUnavailable {
			// Non-retryable gateway error (403, 401, 429, etc.)
			return nil, ge
		}

		lastErr = ge
		if attempt < c.maxRetries {
			backoff := c.backoffBase * (1 << uint(attempt))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.sleepChan(backoff):
			}
		}
	}

	return nil, lastErr
}

// sleepChan performs the backoff sleep and returns a closed channel when done.
// This allows select{} to also check ctx.Done().
func (c *GatewayClient) sleepChan(d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		c.sleep(d)
		close(ch)
	}()
	return ch
}

func (c *GatewayClient) nextID() int64 {
	return c.requestID.Add(1)
}

func isProtocolMethod(methodOrTool string) bool {
	if methodOrTool == "" {
		return false
	}
	// Explicit protocol methods.
	if methodOrTool == "initialize" {
		return true
	}
	if strings.HasPrefix(methodOrTool, "notifications/") {
		return true
	}
	// Any method with a namespace separator is treated as protocol-level
	// (tools/list, tools/call, resources/read, prompts/list, etc.).
	return strings.Contains(methodOrTool, "/")
}

func (c *GatewayClient) doCall(ctx context.Context, methodOrTool string, params map[string]any) (any, error) {
	method := methodOrTool
	effectiveParams := params

	// For tool invocations, use MCP-spec tools/call envelope.
	// This is the primary supported wire format for language/framework agnostic usage.
	if !isProtocolMethod(methodOrTool) {
		if params == nil {
			params = map[string]any{}
		}
		method = "tools/call"
		effectiveParams = map[string]any{
			"name":      methodOrTool,
			"arguments": params,
		}
	}

	// Build JSON-RPC envelope
	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  effectiveParams,
		ID:      c.nextID(),
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to marshal request: %w", err)
	}

	// Build HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", c.spiffeID)
	req.Header.Set("X-Session-ID", c.sessionID)

	// Execute
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mcpgateway: failed to read response: %w", err)
	}

	// Handle HTTP-level errors (denials, rate limits, etc.)
	if resp.StatusCode >= 400 {
		return nil, parseGatewayError(resp.StatusCode, body)
	}

	// Parse JSON-RPC response
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, &GatewayError{
			Code:       "invalid_response",
			Message:    fmt.Sprintf("invalid JSON response (HTTP %d): %s", resp.StatusCode, truncate(string(body), 200)),
			HTTPStatus: resp.StatusCode,
		}
	}

	// Check for JSON-RPC error field
	if rpcResp.Error != nil {
		msg := "unknown error"
		if m, ok := rpcResp.Error["message"]; ok {
			msg = fmt.Sprintf("%v", m)
		}
		return nil, &GatewayError{
			Code:       "jsonrpc_error",
			Message:    fmt.Sprintf("JSON-RPC error: %s", msg),
			HTTPStatus: resp.StatusCode,
		}
	}

	return rpcResp.Result, nil
}

// parseGatewayError attempts to parse a GatewayError from an HTTP error response body.
// Falls back to a generic error if the body is not valid JSON or not the expected format.
func parseGatewayError(statusCode int, body []byte) *GatewayError {
	var ge GatewayError
	if err := json.Unmarshal(body, &ge); err == nil && ge.Code != "" {
		ge.HTTPStatus = statusCode
		return &ge
	}

	// Non-JSON or unrecognized format
	return &GatewayError{
		Code:       "unknown",
		Message:    truncate(string(body), 200),
		HTTPStatus: statusCode,
	}
}

// truncate shortens a string to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
