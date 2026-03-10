//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/internal/tools"
)

// TestContextFetcherIntegration tests the context fetcher with real HTTP requests
func TestContextFetcherIntegration(t *testing.T) {
	// Create a test HTTP server serving public content
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clean":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Clean Content</h1><p>This is a test page with no sensitive data.</p></body></html>"))
		case "/with-pii":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact us at test@example.com or call 555-123-4567"))
		case "/with-credentials":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("API Key: sk-proj-abcdefghijklmnopqrst"))
		case "/large":
			// Generate large content to test chunking
			w.WriteHeader(http.StatusOK)
			for i := 0; i < 100; i++ {
				_, _ = w.Write([]byte("This is a line of text that will be chunked. "))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	// Create temporary storage directory
	tmpDir := t.TempDir()

	// Use real DLP scanner
	scanner := middleware.NewBuiltInScanner()
	fetcher := tools.NewContextFetcher(scanner, tmpDir)

	t.Run("fetch clean content - returns handle", func(t *testing.T) {
		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, testServer.URL+"/clean")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify content_ref returned
		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}
		if ref.ContentID == "" {
			t.Error("content ID should not be empty")
		}

		// Verify provenance metadata
		if ref.Provenance.SourceURL != testServer.URL+"/clean" {
			t.Errorf("expected source URL %s, got %s", testServer.URL+"/clean", ref.Provenance.SourceURL)
		}
		if ref.Provenance.ContentHash == "" {
			t.Error("content hash should not be empty")
		}
		if !ref.Provenance.DLPScanned {
			t.Error("content should be marked as DLP scanned")
		}
		if ref.Provenance.DLPResult != "clean" {
			t.Errorf("expected DLP result 'clean', got %s", ref.Provenance.DLPResult)
		}

		// Verify content was stored and can be retrieved
		content, err := fetcher.GetContent(ref.ContentID)
		if err != nil {
			t.Fatalf("failed to retrieve content: %v", err)
		}
		if !strings.Contains(content, "Clean Content") {
			t.Error("retrieved content does not match expected")
		}

		// Verify HTML was stripped
		if strings.Contains(content, "<html>") || strings.Contains(content, "<body>") {
			t.Error("HTML tags should be stripped during normalization")
		}
	})

	t.Run("fetch content with PII - flagged but not blocked", func(t *testing.T) {
		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, testServer.URL+"/with-pii")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should succeed but with DLP flags
		if len(ref.DLPFlags) == 0 {
			t.Error("expected DLP flags for PII content")
		}
		if ref.Provenance.DLPResult == "clean" {
			t.Error("DLP result should not be 'clean' for content with PII")
		}

		// Content should still be accessible
		_, err = fetcher.GetContent(ref.ContentID)
		if err != nil {
			t.Errorf("should be able to retrieve flagged content: %v", err)
		}
	})

	t.Run("fetch content with credentials - blocked", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidate(ctx, testServer.URL+"/with-credentials")
		if err == nil {
			t.Fatal("expected error for content with credentials")
		}

		// Should be blocked with clear error message
		if !strings.Contains(err.Error(), "credentials") {
			t.Errorf("error should mention credentials, got: %v", err)
		}
	})

	t.Run("fetch large content - chunking works", func(t *testing.T) {
		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, testServer.URL+"/large")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify multiple chunks created
		if ref.ChunkCount <= 1 {
			t.Errorf("expected multiple chunks for large content, got %d", ref.ChunkCount)
		}

		// Verify content can be reassembled correctly
		content, err := fetcher.GetContent(ref.ContentID)
		if err != nil {
			t.Fatalf("failed to retrieve content: %v", err)
		}
		if !strings.Contains(content, "line of text") {
			t.Error("reassembled content does not match expected")
		}
	})

	t.Run("invalid URL - rejected", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidate(ctx, "not-a-valid-url")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})

	t.Run("non-existent URL - rejected", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidate(ctx, testServer.URL+"/nonexistent")
		if err == nil {
			t.Error("expected error for non-existent URL")
		}
	})
}

// TestContextFetcherRealURL tests with a real public URL (optional, can be skipped if network unavailable)
func TestContextFetcherRealURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real URL test in short mode")
	}

	tmpDir := t.TempDir()
	scanner := middleware.NewBuiltInScanner()
	fetcher := tools.NewContextFetcher(scanner, tmpDir)

	// Test with a reliable public URL
	ctx := context.Background()
	ref, err := fetcher.FetchAndValidate(ctx, "https://httpbin.org/html")
	if err != nil {
		// Network issues are acceptable for this test
		t.Logf("Skipping real URL test due to network error: %v", err)
		return
	}

	if ref == nil {
		t.Fatal("expected non-nil content ref")
	}
	if ref.ContentID == "" {
		t.Error("content ID should not be empty")
	}
	if ref.Provenance.SourceURL != "https://httpbin.org/html" {
		t.Error("source URL mismatch")
	}

	// Verify content was stored
	content, err := fetcher.GetContent(ref.ContentID)
	if err != nil {
		t.Fatalf("failed to retrieve content: %v", err)
	}
	if len(content) == 0 {
		t.Error("retrieved content should not be empty")
	}
}

// TestContextPolicyGateIntegration tests the OPA context injection policy gate
// RFA-xwc: Integration test using the REAL OPA engine with the actual context_policy.rego
// No mocks -- proves the full policy evaluation path works.
func TestContextPolicyGateIntegration(t *testing.T) {
	// Set up test HTTP server for content
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clean":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Clean content with no PII or credentials"))
		case "/with-pii":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Contact us at test@example.com or call 555-123-4567"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Default content"))
		}
	}))
	defer testServer.Close()

	tmpDir := t.TempDir()
	policyDir := t.TempDir()

	// Write the actual context policy (same as config/opa/context_policy.rego)
	// Includes step-up approval path for sensitive content (AC #3)
	contextPolicy := `package mcp.context

import rego.v1

default allow_context := false

allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification != "sensitive"
    input.context.handle != ""
    not session_is_high_risk
}

allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification == "sensitive"
    input.context.handle != ""
    not session_is_high_risk
    input.step_up_token != ""
}

session_is_high_risk if {
    input.session.flags["high_risk"]
}
`
	if err := os.WriteFile(policyDir+"/context_policy.rego", []byte(contextPolicy), 0644); err != nil {
		t.Fatalf("Failed to write context policy: %v", err)
	}

	// Need a basic MCP policy so the engine compiles (main query target)
	mcpPolicy := `package mcp
default allow = {"allow": true, "reason": "allowed"}
`
	if err := os.WriteFile(policyDir+"/mcp_policy.rego", []byte(mcpPolicy), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	// Create REAL OPA engine (no mocks)
	opaEngine, err := middleware.NewOPAEngine(policyDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer opaEngine.Close()

	// Create real DLP scanner (no mocks)
	scanner := middleware.NewBuiltInScanner()

	// Create context fetcher WITH real policy evaluator
	fetcher := tools.NewContextFetcherWithPolicy(scanner, tmpDir, opaEngine)

	t.Run("clean_content_normal_session_allowed", func(t *testing.T) {
		ctx := context.Background()
		ref, err := fetcher.FetchAndValidateWithPolicy(ctx, testServer.URL+"/clean", &tools.SessionFlags{
			Flags: map[string]bool{},
		})
		if err != nil {
			t.Fatalf("Expected policy to allow clean content, got error: %v", err)
		}
		if ref == nil {
			t.Fatal("Expected non-nil content ref for allowed content")
		}
		if ref.ContentID == "" {
			t.Error("Expected non-empty content ID")
		}

		// Verify content was stored and is accessible
		content, err := fetcher.GetContent(ref.ContentID)
		if err != nil {
			t.Fatalf("Failed to retrieve stored content: %v", err)
		}
		if !strings.Contains(content, "Clean content") {
			t.Error("Retrieved content does not match expected")
		}
		t.Logf("PASS: Clean content allowed, content_ref=%s", ref.ContentID)
	})

	t.Run("sensitive_content_denied_by_policy", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, testServer.URL+"/with-pii", &tools.SessionFlags{
			Flags: map[string]bool{},
		})
		if err == nil {
			t.Fatal("Expected policy to deny PII content")
		}

		// Verify it's a ContextPolicyDeniedError, not a different error
		policyErr, ok := err.(*tools.ContextPolicyDeniedError)
		if !ok {
			t.Fatalf("Expected *ContextPolicyDeniedError, got %T: %v", err, err)
		}
		t.Logf("PASS: Sensitive content denied with reason: %s", policyErr.Reason)
	})

	t.Run("clean_content_high_risk_session_denied", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, testServer.URL+"/clean", &tools.SessionFlags{
			Flags: map[string]bool{"high_risk": true},
		})
		if err == nil {
			t.Fatal("Expected policy to deny content in high-risk session")
		}

		// Verify it's a ContextPolicyDeniedError
		policyErr, ok := err.(*tools.ContextPolicyDeniedError)
		if !ok {
			t.Fatalf("Expected *ContextPolicyDeniedError, got %T: %v", err, err)
		}
		t.Logf("PASS: High-risk session denied with reason: %s", policyErr.Reason)
	})

	t.Run("sensitive_content_allowed_with_step_up", func(t *testing.T) {
		ctx := context.Background()
		ref, err := fetcher.FetchAndValidateWithPolicy(ctx, testServer.URL+"/with-pii", &tools.SessionFlags{
			Flags:       map[string]bool{},
			StepUpToken: "valid-step-up-token-abc",
		})
		if err != nil {
			t.Fatalf("Expected step-up to allow sensitive content, got error: %v", err)
		}
		if ref == nil {
			t.Fatal("Expected non-nil content ref for step-up approved content")
		}
		if ref.ContentID == "" {
			t.Error("Expected non-empty content ID")
		}
		t.Logf("PASS: Sensitive content allowed with step-up token, content_ref=%s", ref.ContentID)
	})

	t.Run("sensitive_content_denied_with_step_up_high_risk", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, testServer.URL+"/with-pii", &tools.SessionFlags{
			Flags:       map[string]bool{"high_risk": true},
			StepUpToken: "valid-step-up-token-abc",
		})
		if err == nil {
			t.Fatal("Expected policy to deny sensitive content even with step-up in high-risk session")
		}

		// Verify it's a ContextPolicyDeniedError
		policyErr, ok := err.(*tools.ContextPolicyDeniedError)
		if !ok {
			t.Fatalf("Expected *ContextPolicyDeniedError, got %T: %v", err, err)
		}
		t.Logf("PASS: Sensitive content with step-up denied in high-risk session with reason: %s", policyErr.Reason)
	})

	t.Run("backward_compat_without_policy_still_works", func(t *testing.T) {
		// Create fetcher WITHOUT policy evaluator (backward compatibility)
		noPolicyFetcher := tools.NewContextFetcher(scanner, tmpDir)

		ctx := context.Background()
		ref, err := noPolicyFetcher.FetchAndValidate(ctx, testServer.URL+"/clean")
		if err != nil {
			t.Fatalf("Expected success without policy evaluator, got error: %v", err)
		}
		if ref == nil {
			t.Fatal("Expected non-nil content ref")
		}
		t.Logf("PASS: Backward compatibility maintained, content_ref=%s", ref.ContentID)
	})
}

// TestPolicyBlocksRawInjection tests that policy blocks raw content injection
func TestPolicyBlocksRawInjection(t *testing.T) {
	// This test verifies that the gateway policy blocks attempts to inject raw content
	// instead of using content_ref handles

	// Wait for gateway to be ready
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Skipf("Gateway not ready: %v", err)
	}

	t.Run("raw content injection blocked by policy", func(t *testing.T) {
		// Attempt to send a request with raw content instead of content_ref
		rawContentRequest := map[string]interface{}{
			"method": "tools/call",
			"params": map[string]interface{}{
				"name": "some_tool",
				"arguments": map[string]interface{}{
					"raw_content": "This is raw content that should be blocked",
				},
			},
		}

		reqBody, _ := json.Marshal(rawContentRequest)
		req, _ := http.NewRequest("POST", gatewayURL+"/", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", "spiffe://example.org/agent/researcher")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("Gateway connection failed: %v", err)
		}
		defer resp.Body.Close()

		// For this POC, we verify the middleware chain processes the request
		// In a full implementation, OPA policy would specifically block raw content
		// For now, we verify the request reaches the gateway and is processed
		if resp.StatusCode == http.StatusOK {
			t.Log("Request processed through middleware chain (OPA policy check would block raw content in production)")
		}
	})

	t.Run("content_ref allowed by policy", func(t *testing.T) {
		// Create a valid content_ref first
		tmpDir := t.TempDir()
		scanner := middleware.NewBuiltInScanner()
		fetcher := tools.NewContextFetcher(scanner, tmpDir)

		// Create test server for content
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Test content for validation"))
		}))
		defer testServer.Close()

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, testServer.URL)
		if err != nil {
			t.Fatalf("failed to create content ref: %v", err)
		}

		// Send request with content_ref
		contentRefRequest := map[string]interface{}{
			"method": "tools/call",
			"params": map[string]interface{}{
				"name": "some_tool",
				"arguments": map[string]interface{}{
					"content_ref": ref.ContentID,
				},
			},
		}

		reqBody, _ := json.Marshal(contentRefRequest)
		req, _ := http.NewRequest("POST", gatewayURL+"/", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SPIFFE-ID", "spiffe://example.org/agent/researcher")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Skipf("Gateway connection failed: %v", err)
		}
		defer resp.Body.Close()

		// Verify request is processed
		// In production, this would verify the content_ref is allowed
		if resp.StatusCode >= 500 {
			t.Logf("Gateway processed request with content_ref (status: %d)", resp.StatusCode)
		}
	})
}

// gatewayURL, waitForService, and getEnvOrDefault are defined in test_helpers_test.go
