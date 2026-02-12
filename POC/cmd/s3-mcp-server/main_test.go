// S3 MCP Tool Server Tests - RFA-9fv.5
//
// Unit tests for:
//   - Allowlist enforcement (positive and negative)
//   - Tool schema hashing (verifies registry hashes match)
//   - JSON-RPC protocol handling (tools/list, tools/call, errors)
//   - Allowlist parsing from environment variable format
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// mockS3Client implements S3Client for testing without real AWS calls.
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

// --- Allowlist enforcement tests ---

func TestIsAllowed_ExactMatch(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if !srv.IsAllowed("my-bucket", "data/file.txt") {
		t.Error("expected allowed for matching bucket and prefix")
	}
	if !srv.IsAllowed("my-bucket", "data/") {
		t.Error("expected allowed for exact prefix match")
	}
}

func TestIsAllowed_Denied_WrongBucket(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if srv.IsAllowed("other-bucket", "data/file.txt") {
		t.Error("expected denied for wrong bucket")
	}
}

func TestIsAllowed_Denied_WrongPrefix(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/"},
	})

	if srv.IsAllowed("my-bucket", "secret/file.txt") {
		t.Error("expected denied for wrong prefix")
	}
}

func TestIsAllowed_Denied_PrefixTraversal(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: "data/public/"},
	})

	// Attempting path traversal should be blocked since it doesn't start with prefix
	if srv.IsAllowed("my-bucket", "../secret/file.txt") {
		t.Error("expected denied for path traversal attempt")
	}
	if srv.IsAllowed("my-bucket", "data/../secret/file.txt") {
		t.Error("expected denied for embedded traversal (does not start with data/public/)")
	}
}

func TestIsAllowed_MultipleEntries(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "bucket-a", Prefix: "logs/"},
		{Bucket: "bucket-b", Prefix: "reports/"},
	})

	if !srv.IsAllowed("bucket-a", "logs/2024/jan.log") {
		t.Error("expected allowed for bucket-a logs/")
	}
	if !srv.IsAllowed("bucket-b", "reports/q1.pdf") {
		t.Error("expected allowed for bucket-b reports/")
	}
	if srv.IsAllowed("bucket-a", "reports/q1.pdf") {
		t.Error("expected denied for bucket-a reports/ (wrong prefix)")
	}
}

func TestIsAllowed_EmptyAllowlist(t *testing.T) {
	srv := NewMCPServer(nil, nil)

	if srv.IsAllowed("any-bucket", "any-key") {
		t.Error("expected denied with empty allowlist")
	}
}

func TestIsAllowed_EmptyPrefix(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "my-bucket", Prefix: ""},
	})

	// Empty prefix means entire bucket is allowed
	if !srv.IsAllowed("my-bucket", "anything/goes/here.txt") {
		t.Error("expected allowed with empty prefix (entire bucket)")
	}
}

// --- Allowlist parsing tests ---

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []AllowlistEntry
	}{
		{
			name:     "single entry",
			input:    "my-bucket:data/",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: "data/"}},
		},
		{
			name:  "multiple entries",
			input: "bucket-a:logs/,bucket-b:reports/",
			expected: []AllowlistEntry{
				{Bucket: "bucket-a", Prefix: "logs/"},
				{Bucket: "bucket-b", Prefix: "reports/"},
			},
		},
		{
			name:     "bucket only (no prefix)",
			input:    "my-bucket",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: ""}},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "whitespace trimming",
			input: " bucket-a:data/ , bucket-b:logs/ ",
			expected: []AllowlistEntry{
				{Bucket: "bucket-a", Prefix: "data/"},
				{Bucket: "bucket-b", Prefix: "logs/"},
			},
		},
		{
			name:     "prefix with colon",
			input:    "my-bucket:path:with:colons/",
			expected: []AllowlistEntry{{Bucket: "my-bucket", Prefix: "path:with:colons/"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseAllowlist(tc.input)
			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d entries, got %d", len(tc.expected), len(result))
			}
			for i, r := range result {
				if r.Bucket != tc.expected[i].Bucket || r.Prefix != tc.expected[i].Prefix {
					t.Errorf("entry %d: expected {%q, %q}, got {%q, %q}",
						i, tc.expected[i].Bucket, tc.expected[i].Prefix, r.Bucket, r.Prefix)
				}
			}
		})
	}
}

// --- Tool schema hash verification tests ---

func TestToolSchemaHash_S3ListObjects(t *testing.T) {
	hash := middleware.ComputeHash(S3ListObjectsDescription, S3ListObjectsSchema())
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	// Verify the hash is a valid hex string of 64 chars (SHA-256)
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
	}
	// Verify the hash matches what is registered in tool-registry.yaml
	const expectedHash = "8e007a4ef7ffb625b72e43f04febb0f7409435f9551018b6dbb3d3858fcef0ea"
	if hash != expectedHash {
		t.Errorf("hash mismatch with tool-registry.yaml:\n  computed: %s\n  expected: %s", hash, expectedHash)
	}
	t.Logf("s3_list_objects hash: %s", hash)
}

func TestToolSchemaHash_S3GetObject(t *testing.T) {
	hash := middleware.ComputeHash(S3GetObjectDescription, S3GetObjectSchema())
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
	}
	// Verify the hash matches what is registered in tool-registry.yaml
	const expectedHash = "c2fd4dfceb57d856cdf0bdf9d50d64798dae998d5e107b28220f2fea76c7f7f4"
	if hash != expectedHash {
		t.Errorf("hash mismatch with tool-registry.yaml:\n  computed: %s\n  expected: %s", hash, expectedHash)
	}
	t.Logf("s3_get_object hash: %s", hash)
}

func TestToolSchemaHash_Deterministic(t *testing.T) {
	hash1 := middleware.ComputeHash(S3ListObjectsDescription, S3ListObjectsSchema())
	hash2 := middleware.ComputeHash(S3ListObjectsDescription, S3ListObjectsSchema())
	if hash1 != hash2 {
		t.Errorf("hash is not deterministic: %s != %s", hash1, hash2)
	}
}

// --- JSON-RPC protocol tests ---

func TestHandleToolsList(t *testing.T) {
	srv := NewMCPServer(nil, nil)
	resp := srv.HandleToolsList(1)

	if resp.Jsonrpc != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", resp.Jsonrpc)
	}
	if resp.ID != 1 {
		t.Errorf("expected id 1, got %v", resp.ID)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result should be a map")
	}
	tools, ok := result["tools"].([]ToolDefinition)
	if !ok {
		t.Fatal("tools should be []ToolDefinition")
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "s3_list_objects" {
		t.Errorf("expected first tool name s3_list_objects, got %s", tools[0].Name)
	}
	if tools[1].Name != "s3_get_object" {
		t.Errorf("expected second tool name s3_get_object, got %s", tools[1].Name)
	}
}

func TestHandleToolsCall_ListObjects_Success(t *testing.T) {
	now := time.Now()
	mock := &mockS3Client{
		listResult: &s3.ListObjectsV2Output{
			Contents: []s3types.Object{
				{Key: aws.String("data/file1.txt"), Size: aws.Int64(100), LastModified: &now},
				{Key: aws.String("data/file2.txt"), Size: aws.Int64(200), LastModified: &now},
			},
		},
	}
	srv := NewMCPServer(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 1, ToolCallParams{
		Name: "s3_list_objects",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"prefix": "data/",
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if result.IsError {
		t.Error("result should not be an error")
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}
	if !strings.Contains(result.Content[0].Text, "data/file1.txt") {
		t.Error("result should contain file1.txt")
	}
	if !strings.Contains(result.Content[0].Text, "data/file2.txt") {
		t.Error("result should contain file2.txt")
	}
	if !strings.Contains(result.Content[0].Text, "count: 2") {
		t.Error("result should contain count: 2")
	}
}

func TestHandleToolsCall_ListObjects_Denied(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 1, ToolCallParams{
		Name: "s3_list_objects",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"prefix": "secret/",
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %v", resp.Error)
	}
	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("result should be an error (access denied)")
	}
	if !strings.Contains(result.Content[0].Text, "access denied") {
		t.Errorf("expected access denied message, got: %s", result.Content[0].Text)
	}
}

func TestHandleToolsCall_GetObject_Success(t *testing.T) {
	mock := &mockS3Client{
		getResult: &s3.GetObjectOutput{
			Body: io.NopCloser(strings.NewReader("hello world")),
		},
	}
	srv := NewMCPServer(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 2, ToolCallParams{
		Name: "s3_get_object",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"key":    "data/file.txt",
		},
	})

	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if result.IsError {
		t.Error("result should not be an error")
	}
	if result.Content[0].Text != "hello world" {
		t.Errorf("expected 'hello world', got %q", result.Content[0].Text)
	}
}

func TestHandleToolsCall_GetObject_Denied(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 2, ToolCallParams{
		Name: "s3_get_object",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"key":    "secret/passwords.txt",
		},
	})

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("result should be an error (access denied)")
	}
	if !strings.Contains(result.Content[0].Text, "access denied") {
		t.Error("expected access denied message")
	}
}

func TestHandleToolsCall_UnknownTool(t *testing.T) {
	srv := NewMCPServer(nil, nil)

	resp := srv.HandleToolsCall(context.Background(), 3, ToolCallParams{
		Name:      "unknown_tool",
		Arguments: nil,
	})

	if resp.Error == nil {
		t.Fatal("expected error for unknown tool")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
}

func TestHandleToolsCall_MissingRequiredParams(t *testing.T) {
	srv := NewMCPServer(nil, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	// s3_list_objects with empty bucket
	resp := srv.HandleToolsCall(context.Background(), 1, ToolCallParams{
		Name: "s3_list_objects",
		Arguments: map[string]interface{}{
			"bucket": "",
			"prefix": "data/",
		},
	})

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("expected error for empty bucket")
	}
	if !strings.Contains(result.Content[0].Text, "required") {
		t.Error("expected 'required' in error message")
	}

	// s3_get_object with empty key
	resp = srv.HandleToolsCall(context.Background(), 2, ToolCallParams{
		Name: "s3_get_object",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"key":    "",
		},
	})

	result, ok = resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("expected error for empty key")
	}
}

// --- HTTP handler tests ---

func TestHTTP_HealthCheck(t *testing.T) {
	srv := NewMCPServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status ok, got %s", body["status"])
	}
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	srv := NewMCPServer(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_ToolsList(t *testing.T) {
	srv := NewMCPServer(nil, nil)

	body, _ := json.Marshal(JSONRPCRequest{
		Jsonrpc: "2.0",
		Method:  "tools/list",
		ID:      1,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

func TestHTTP_ToolsCall_WithAllowedRequest(t *testing.T) {
	now := time.Now()
	mock := &mockS3Client{
		listResult: &s3.ListObjectsV2Output{
			Contents: []s3types.Object{
				{Key: aws.String("data/test.txt"), Size: aws.Int64(42), LastModified: &now},
			},
		},
	}
	srv := NewMCPServer(mock, []AllowlistEntry{
		{Bucket: "allowed-bucket", Prefix: "data/"},
	})

	params, _ := json.Marshal(ToolCallParams{
		Name: "s3_list_objects",
		Arguments: map[string]interface{}{
			"bucket": "allowed-bucket",
			"prefix": "data/",
		},
	})
	body, _ := json.Marshal(JSONRPCRequest{
		Jsonrpc: "2.0",
		Method:  "tools/call",
		Params:  params,
		ID:      1,
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Errorf("unexpected JSON-RPC error: %v", resp.Error)
	}
}

func TestHTTP_UnknownMethod(t *testing.T) {
	srv := NewMCPServer(nil, nil)

	body, _ := json.Marshal(JSONRPCRequest{
		Jsonrpc: "2.0",
		Method:  "unknown/method",
		ID:      1,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected -32601, got %d", resp.Error.Code)
	}
}

func TestHTTP_InvalidJSON(t *testing.T) {
	srv := NewMCPServer(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == nil {
		t.Error("expected parse error")
	}
	if resp.Error.Code != -32700 {
		t.Errorf("expected -32700, got %d", resp.Error.Code)
	}
}

func TestHandleToolsCall_ListObjects_S3Error(t *testing.T) {
	mock := &mockS3Client{
		listErr: io.ErrUnexpectedEOF,
	}
	srv := NewMCPServer(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 1, ToolCallParams{
		Name: "s3_list_objects",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"prefix": "data/",
		},
	})

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("expected error on S3 failure")
	}
	if !strings.Contains(result.Content[0].Text, "ListObjectsV2 failed") {
		t.Error("expected S3 error message")
	}
}

func TestHandleToolsCall_GetObject_S3Error(t *testing.T) {
	mock := &mockS3Client{
		getErr: io.ErrUnexpectedEOF,
	}
	srv := NewMCPServer(mock, []AllowlistEntry{
		{Bucket: "test-bucket", Prefix: "data/"},
	})

	resp := srv.HandleToolsCall(context.Background(), 2, ToolCallParams{
		Name: "s3_get_object",
		Arguments: map[string]interface{}{
			"bucket": "test-bucket",
			"key":    "data/file.txt",
		},
	})

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("result should be *ToolResult")
	}
	if !result.IsError {
		t.Error("expected error on S3 failure")
	}
	if !strings.Contains(result.Content[0].Text, "GetObject failed") {
		t.Error("expected S3 error message")
	}
}
