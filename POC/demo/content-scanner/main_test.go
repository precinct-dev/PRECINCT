package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// errorScanner is a test Scanner that always returns an error.
type errorScanner struct{}

func (e *errorScanner) Scan(_ context.Context, _ []byte, _ ScanMetadata) (ScanResult, error) {
	return ScanResult{}, errors.New("scanner internal failure")
}

// buildExtensionRequest creates a properly formed ExtensionRequest JSON with
// the given content base64-encoded in the body field.
func buildExtensionRequest(t *testing.T, content string) []byte {
	t.Helper()
	body := base64.StdEncoding.EncodeToString([]byte(content))
	req := ExtensionRequest{
		Version:   "1.0.0",
		RequestID: "test-req-001",
		TraceID:   "test-trace-001",
		Timestamp: "2026-02-22T00:00:00Z",
		Slot:      "pre_tool",
	}
	req.Request.Method = "POST"
	req.Request.ToolName = "code_executor"
	req.Request.Body = body
	req.Request.SPIFFEID = "spiffe://example.org/test"
	req.Request.SecurityFlags = []string{"mcp_request"}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal extension request: %v", err)
	}
	return data
}

func TestHealthEndpoint(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", body["status"])
	}
}

func TestScanEndpoint_CleanContent(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := buildExtensionRequest(t, "Hello, this is a perfectly normal message.")
	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %q", extResp.Decision)
	}
	if extResp.HTTPStatus != 0 {
		t.Errorf("expected no http_status for allow, got %d", extResp.HTTPStatus)
	}
}

func TestScanEndpoint_PromptInjection(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := buildExtensionRequest(t, `<script>alert("xss")</script>`)
	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "block" {
		t.Errorf("expected decision 'block', got %q", extResp.Decision)
	}
	if extResp.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected http_status 403, got %d", extResp.HTTPStatus)
	}
	if extResp.ErrorCode != "ext_content_scanner_blocked" {
		t.Errorf("expected error_code 'ext_content_scanner_blocked', got %q", extResp.ErrorCode)
	}
}

func TestScanEndpoint_EvalPattern(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := buildExtensionRequest(t, "result = eval(userInput)")
	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "flag" {
		t.Errorf("expected decision 'flag', got %q", extResp.Decision)
	}
	if len(extResp.Flags) == 0 {
		t.Error("expected flags to be populated for flagged content")
	}
	// Flag decisions should not have http_status or error_code
	if extResp.HTTPStatus != 0 {
		t.Errorf("expected no http_status for flag, got %d", extResp.HTTPStatus)
	}
}

func TestScanEndpoint_MalformedJSON(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader([]byte("not-valid-json{{")))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "block" {
		t.Errorf("expected decision 'block' for malformed JSON, got %q", extResp.Decision)
	}
	if extResp.ErrorCode != "ext_content_scanner_bad_request" {
		t.Errorf("expected error_code 'ext_content_scanner_bad_request', got %q", extResp.ErrorCode)
	}
}

func TestScanEndpoint_EmptyBody(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Build request with empty body field
	req := ExtensionRequest{
		Version:   "1.0.0",
		RequestID: "test-req-empty",
		Slot:      "pre_tool",
	}
	// Body is intentionally left empty (zero value "")
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "allow" {
		t.Errorf("expected decision 'allow' for empty body, got %q", extResp.Decision)
	}
}

func TestInfoEndpoint(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/info")
	if err != nil {
		t.Fatalf("GET /info failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("failed to decode info response: %v", err)
	}
	if info.Name != "content-scanner" {
		t.Errorf("expected name 'content-scanner', got %q", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", info.Version)
	}
	if info.PatternCount != 12 {
		t.Errorf("expected pattern_count 12, got %d", info.PatternCount)
	}
}

func TestScanEndpoint_MethodNotAllowed(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/scan")
	if err != nil {
		t.Fatalf("GET /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestScanEndpoint_CredentialBlock(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := buildExtensionRequest(t, "AKIAIOSFODNN7EXAMPLE1")
	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "block" {
		t.Errorf("expected decision 'block' for AWS key, got %q", extResp.Decision)
	}
	if extResp.HTTPStatus != http.StatusForbidden {
		t.Errorf("expected http_status 403, got %d", extResp.HTTPStatus)
	}
}

func TestScanEndpoint_InvalidBase64(t *testing.T) {
	scanner := NewPatternScanner()
	mux := newMux(scanner, scanner.PatternCount())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Build a request with an invalid base64 body
	req := ExtensionRequest{
		Version:   "1.0.0",
		RequestID: "test-req-bad-b64",
		Slot:      "pre_tool",
	}
	req.Request.Body = "!!!not-valid-base64!!!"

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "block" {
		t.Errorf("expected decision 'block' for invalid base64, got %q", extResp.Decision)
	}
	if extResp.ErrorCode != "ext_content_scanner_bad_request" {
		t.Errorf("expected error_code 'ext_content_scanner_bad_request', got %q", extResp.ErrorCode)
	}
}

func TestScanEndpoint_ScannerError(t *testing.T) {
	// Use the errorScanner to trigger the scanner error path
	mux := newMux(&errorScanner{}, 0)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := buildExtensionRequest(t, "some content")
	resp, err := http.Post(ts.URL+"/scan", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /scan failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	var extResp ExtensionResponse
	if err := json.NewDecoder(resp.Body).Decode(&extResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if extResp.Decision != "block" {
		t.Errorf("expected decision 'block' for scanner error, got %q", extResp.Decision)
	}
	if extResp.ErrorCode != "ext_content_scanner_error" {
		t.Errorf("expected error_code 'ext_content_scanner_error', got %q", extResp.ErrorCode)
	}
}
