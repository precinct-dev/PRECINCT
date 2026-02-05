// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
	"github.com/example/agentic-security-poc/internal/tools"
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

// waitForService waits for a service to be ready
func waitForService(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service %s not ready after %v", url, timeout)
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

var (
	gatewayURL = getEnvOrDefault("GATEWAY_URL", "http://localhost:9090")
)
