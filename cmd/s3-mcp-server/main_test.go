// S3 MCP server integration tests -- verify that the s3adapter tools work
// correctly when wired through the mcpserver framework. These tests exercise
// the full HTTP JSON-RPC path: session init -> tools/list -> tools/call.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/precinct-dev/precinct/cmd/s3-mcp-server/s3adapter"
	"github.com/precinct-dev/precinct/pkg/mcpserver"
)

// mockS3Client implements s3adapter.S3Client for testing.
type mockS3Client struct {
	listResult *s3.ListObjectsV2Output
	listErr    error
	getResult  *s3.GetObjectOutput
	getErr     error
}

func (m *mockS3Client) ListObjectsV2(_ context.Context, _ *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return m.listResult, m.listErr
}

func (m *mockS3Client) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return m.getResult, m.getErr
}

// jsonrpcRequest mirrors the wire format for JSON-RPC requests.
type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// jsonrpcResponse mirrors the wire format for JSON-RPC responses.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// toolCallResult mirrors the MCP tool call result wire format.
type toolCallResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError,omitempty"`
}

// startTestServer creates a framework server with the given mock and allowlist,
// starts it on an ephemeral port, and returns the base URL and a cancel function.
func startTestServer(t *testing.T, mock s3adapter.S3Client, allowlist []s3adapter.AllowlistEntry) (string, context.CancelFunc) {
	t.Helper()

	adapter := s3adapter.New(mock, allowlist)
	srv := mcpserver.New("s3-mcp-server-test",
		mcpserver.WithPort(0),
		mcpserver.WithoutOTel(),
		mcpserver.WithoutCaching(),
		mcpserver.WithoutRateLimiting(),
	)
	srv.Tool("s3_list_objects", s3adapter.ListObjectsDescription, s3adapter.ListObjectsSchema(), adapter.ListObjects)
	srv.Tool("s3_get_object", s3adapter.GetObjectDescription, s3adapter.GetObjectSchema(), adapter.GetObject)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.RunContext(ctx)
	}()

	// Wait for the server to start listening.
	var baseURL string
	for i := 0; i < 50; i++ {
		if addr := srv.Addr(); addr != nil {
			baseURL = fmt.Sprintf("http://%s", addr.String())
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if baseURL == "" {
		cancel()
		t.Fatal("server did not start in time")
	}

	t.Cleanup(func() {
		cancel()
		// Drain the error channel.
		<-errCh
	})

	return baseURL, cancel
}

// initSession performs the MCP initialize + notifications/initialized handshake
// and returns the session ID.
func initSession(t *testing.T, baseURL string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}

	// Step 1: initialize
	initReq, _ := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      json.RawMessage(`1`),
	})
	resp, err := client.Post(baseURL+"/", "application/json", bytes.NewReader(initReq))
	if err != nil {
		t.Fatalf("initialize request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", resp.StatusCode)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatal("initialize: no Mcp-Session-Id header")
	}

	// Step 2: notifications/initialized
	notifReq, _ := json.Marshal(jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/", bytes.NewReader(notifReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("notifications/initialized failed: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("notifications/initialized: expected 200, got %d", resp2.StatusCode)
	}

	return sessionID
}

// doRPC sends a JSON-RPC request with session header and returns the parsed response.
func doRPC(t *testing.T, baseURL, sessionID string, req jsonrpcRequest) jsonrpcResponse {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}

	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest(http.MethodPost, baseURL+"/", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Mcp-Session-Id", sessionID)

	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("RPC request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rpcResp jsonrpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return rpcResp
}

// --- Integration tests ---

func TestIntegration_HealthCheck(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %s", body["status"])
	}
}

func TestIntegration_ToolsList(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, nil)
	sessionID := initSession(t, baseURL)

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      json.RawMessage(`2`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Parse the tools list result.
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tools list: %v", err)
	}
	if len(result.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(result.Tools))
	}
	if result.Tools[0].Name != "s3_list_objects" {
		t.Errorf("expected first tool s3_list_objects, got %s", result.Tools[0].Name)
	}
	if result.Tools[1].Name != "s3_get_object" {
		t.Errorf("expected second tool s3_get_object, got %s", result.Tools[1].Name)
	}
}

func TestIntegration_ListObjects_Success(t *testing.T) {
	now := time.Now()
	mock := &mockS3Client{
		listResult: &s3.ListObjectsV2Output{
			Contents: []s3types.Object{
				{Key: aws.String("data/test.txt"), Size: aws.Int64(42), LastModified: &now},
			},
		},
	}
	baseURL, _ := startTestServer(t, mock, []s3adapter.AllowlistEntry{
		{Bucket: "allowed-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_list_objects",
		"arguments": map[string]any{
			"bucket": "allowed-bucket",
			"prefix": "data/",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`3`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if result.IsError {
		t.Errorf("expected success, got error: %s", result.Content[0].Text)
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "data/test.txt") {
		t.Error("result should contain data/test.txt")
	}
}

func TestIntegration_ListObjects_Denied(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, []s3adapter.AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_list_objects",
		"arguments": map[string]any{
			"bucket": "test-bucket",
			"prefix": "secret/",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`4`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if !result.IsError {
		t.Error("expected isError for access denied")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "access denied") {
		t.Error("expected access denied message")
	}
}

func TestIntegration_GetObject_Success(t *testing.T) {
	mock := &mockS3Client{
		getResult: &s3.GetObjectOutput{
			Body: io.NopCloser(strings.NewReader("hello world")),
		},
	}
	baseURL, _ := startTestServer(t, mock, []s3adapter.AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_get_object",
		"arguments": map[string]any{
			"bucket": "test-bucket",
			"key":    "data/file.txt",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`5`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if result.IsError {
		t.Error("expected success result")
	}
	if len(result.Content) == 0 || result.Content[0].Text != "hello world" {
		t.Errorf("expected 'hello world', got %q", result.Content[0].Text)
	}
}

func TestIntegration_GetObject_Denied(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, []s3adapter.AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_get_object",
		"arguments": map[string]any{
			"bucket": "test-bucket",
			"key":    "secret/passwords.txt",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`6`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if !result.IsError {
		t.Error("expected isError for access denied")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "access denied") {
		t.Error("expected access denied message")
	}
}

func TestIntegration_UnknownMethod(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, nil)
	sessionID := initSession(t, baseURL)

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "unknown/method",
		ID:      json.RawMessage(`7`),
	})

	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
	if resp.Error != nil && resp.Error.Code != -32601 {
		t.Errorf("expected -32601, got %d", resp.Error.Code)
	}
}

func TestIntegration_InvalidJSON(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Post(baseURL+"/", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rpcResp jsonrpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Error("expected parse error")
	}
	if rpcResp.Error != nil && rpcResp.Error.Code != -32700 {
		t.Errorf("expected -32700, got %d", rpcResp.Error.Code)
	}
}

func TestIntegration_MethodNotAllowed(t *testing.T) {
	baseURL, _ := startTestServer(t, nil, nil)
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestIntegration_ListObjects_S3Error(t *testing.T) {
	mock := &mockS3Client{
		listErr: io.ErrUnexpectedEOF,
	}
	baseURL, _ := startTestServer(t, mock, []s3adapter.AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_list_objects",
		"arguments": map[string]any{
			"bucket": "test-bucket",
			"prefix": "data/",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`8`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if !result.IsError {
		t.Error("expected error on S3 failure")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "ListObjectsV2 failed") {
		t.Error("expected S3 error message")
	}
}

func TestIntegration_GetObject_S3Error(t *testing.T) {
	mock := &mockS3Client{
		getErr: io.ErrUnexpectedEOF,
	}
	baseURL, _ := startTestServer(t, mock, []s3adapter.AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})
	sessionID := initSession(t, baseURL)

	params, _ := json.Marshal(map[string]any{
		"name": "s3_get_object",
		"arguments": map[string]any{
			"bucket": "test-bucket",
			"key":    "data/file.txt",
		},
	})

	resp := doRPC(t, baseURL, sessionID, jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      json.RawMessage(`9`),
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}

	var result toolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tool result: %v", err)
	}
	if !result.IsError {
		t.Error("expected error on S3 failure")
	}
	if len(result.Content) == 0 || !strings.Contains(result.Content[0].Text, "GetObject failed") {
		t.Error("expected S3 error message")
	}
}
