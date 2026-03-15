package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

// mockDLPScanner for testing
type mockDLPScanner struct {
	result middleware.ScanResult
}

func (m *mockDLPScanner) Scan(content string) middleware.ScanResult {
	return m.result
}

// mockContextPolicyEvaluator for testing OPA context policy gate
// RFA-xwc: Used in unit tests to verify the policy gate integration
type mockContextPolicyEvaluator struct {
	allow  bool
	reason string
	err    error
	// lastInput captures the input for verification
	lastInput middleware.ContextPolicyInput
}

func (m *mockContextPolicyEvaluator) EvaluateContextPolicy(input middleware.ContextPolicyInput) (bool, string, error) {
	m.lastInput = input
	return m.allow, m.reason, m.err
}

func TestNewContextFetcher(t *testing.T) {
	scanner := &mockDLPScanner{}
	storageDir := "/tmp/test-storage"

	fetcher := NewContextFetcher(scanner, storageDir)

	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
	if fetcher.scanner != scanner {
		t.Error("scanner not set correctly")
	}
	if fetcher.storageDir != storageDir {
		t.Error("storage dir not set correctly")
	}
	if fetcher.httpClient == nil {
		t.Error("http client not initialized")
	}
}

func TestNormalizeContent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strips HTML tags",
			input:    "<html><body><p>Hello World</p></body></html>",
			expected: "Hello World",
		},
		{
			name:     "collapses whitespace",
			input:    "Hello    World\n\n\nTest",
			expected: "Hello World Test",
		},
		{
			name:     "trims leading and trailing whitespace",
			input:    "  Hello World  ",
			expected: "Hello World",
		},
		{
			name:     "handles mixed HTML and text",
			input:    "<div>Hello <span>World</span></div> Test",
			expected: "Hello World Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeContent(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestChunkContent(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		chunkSize  int
		wantChunks int
	}{
		{
			name:       "single chunk",
			content:    "Hello",
			chunkSize:  10,
			wantChunks: 1,
		},
		{
			name:       "multiple chunks",
			content:    "Hello World Test",
			chunkSize:  5,
			wantChunks: 4, // "Hello", " Worl", "d Tes", "t"
		},
		{
			name:       "exact chunk size",
			content:    "12345",
			chunkSize:  5,
			wantChunks: 1,
		},
		{
			name:       "empty content",
			content:    "",
			chunkSize:  10,
			wantChunks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := chunkContent(tt.content, tt.chunkSize)
			if len(chunks) != tt.wantChunks {
				t.Errorf("expected %d chunks, got %d", tt.wantChunks, len(chunks))
			}

			// Verify reassembled content matches original
			var reassembled strings.Builder
			for _, chunk := range chunks {
				reassembled.WriteString(chunk)
			}
			if reassembled.String() != tt.content {
				t.Error("reassembled content does not match original")
			}
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		valid bool
	}{
		{
			name:  "valid HTTP URL",
			url:   "http://example.com",
			valid: true,
		},
		{
			name:  "valid HTTPS URL",
			url:   "https://example.com/path",
			valid: true,
		},
		{
			name:  "invalid - no scheme",
			url:   "example.com",
			valid: false,
		},
		{
			name:  "invalid - ftp scheme",
			url:   "ftp://example.com",
			valid: false,
		},
		{
			name:  "invalid - too short",
			url:   "http://",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidURL(tt.url)
			if result != tt.valid {
				t.Errorf("expected %v, got %v", tt.valid, result)
			}
		})
	}
}

func TestFormatDLPResult(t *testing.T) {
	tests := []struct {
		name     string
		result   middleware.ScanResult
		expected string
	}{
		{
			name: "clean content",
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				HasSuspicious:  false,
			},
			expected: "clean",
		},
		{
			name: "has credentials",
			result: middleware.ScanResult{
				HasCredentials: true,
			},
			expected: "credentials",
		},
		{
			name: "has PII",
			result: middleware.ScanResult{
				HasPII: true,
			},
			expected: "pii",
		},
		{
			name: "has suspicious",
			result: middleware.ScanResult{
				HasSuspicious: true,
			},
			expected: "suspicious",
		},
		{
			name: "multiple flags",
			result: middleware.ScanResult{
				HasCredentials: true,
				HasPII:         true,
			},
			expected: "credentials,pii",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDLPResult(tt.result)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFetchContent(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("test content"))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	scanner := &mockDLPScanner{}
	fetcher := NewContextFetcher(scanner, "/tmp/test")

	t.Run("successful fetch", func(t *testing.T) {
		ctx := context.Background()
		content, err := fetcher.fetchContent(ctx, server.URL+"/ok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if content != "test content" {
			t.Errorf("expected 'test content', got %q", content)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.fetchContent(ctx, server.URL+"/notfound")
		if err == nil {
			t.Error("expected error for 404 response")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		ctx := context.Background()
		_, err := fetcher.fetchContent(ctx, "not-a-url")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

func TestStoreAndGetContent(t *testing.T) {
	// Create temporary storage directory
	tmpDir := t.TempDir()

	scanner := &mockDLPScanner{}
	fetcher := NewContextFetcher(scanner, tmpDir)

	contentID := "test-content-id"
	chunks := []string{"chunk 1", "chunk 2", "chunk 3"}

	t.Run("store content", func(t *testing.T) {
		err := fetcher.storeContent(contentID, chunks)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify directory exists
		contentDir := filepath.Join(tmpDir, contentID)
		if _, err := os.Stat(contentDir); os.IsNotExist(err) {
			t.Error("content directory not created")
		}

		// Verify chunk files exist
		for i := range chunks {
			chunkFile := filepath.Join(contentDir, "chunk_"+string(rune('0'+i))+".txt")
			if _, err := os.Stat(chunkFile); os.IsNotExist(err) {
				t.Errorf("chunk file %d not created", i)
			}
		}

		// Verify metadata file exists
		metadataFile := filepath.Join(contentDir, "metadata.json")
		if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
			t.Error("metadata file not created")
		}
	})

	t.Run("get content", func(t *testing.T) {
		content, err := fetcher.GetContent(contentID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := strings.Join(chunks, "")
		if content != expected {
			t.Errorf("expected %q, got %q", expected, content)
		}
	})

	t.Run("get non-existent content", func(t *testing.T) {
		_, err := fetcher.GetContent("non-existent-id")
		if err == nil {
			t.Error("expected error for non-existent content")
		}
	})
}

func TestFetchAndValidate(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Test content</body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	t.Run("successful fetch and validate", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		fetcher := NewContextFetcher(scanner, tmpDir)

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}
		if ref.ContentID == "" {
			t.Error("content ID not set")
		}
		if ref.Provenance.SourceURL != server.URL {
			t.Errorf("expected source URL %s, got %s", server.URL, ref.Provenance.SourceURL)
		}
		if ref.Provenance.ContentHash == "" {
			t.Error("content hash not set")
		}
		if !ref.Provenance.DLPScanned {
			t.Error("DLP scanned flag not set")
		}
		if ref.ChunkCount == 0 {
			t.Error("chunk count should be greater than 0")
		}
	})

	t.Run("blocked by DLP - credentials", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: true,
				Flags:          []string{"blocked_content"},
			},
		}
		fetcher := NewContextFetcher(scanner, tmpDir)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidate(ctx, server.URL)
		if err == nil {
			t.Error("expected error for content with credentials")
		}
		if !strings.Contains(err.Error(), "credentials") {
			t.Errorf("expected credentials error, got: %v", err)
		}
	})

	t.Run("flagged but not blocked - PII", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         true,
				Flags:          []string{"potential_pii"},
			},
		}
		fetcher := NewContextFetcher(scanner, tmpDir)

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ref.DLPFlags) == 0 {
			t.Error("expected DLP flags for PII content")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		scanner := &mockDLPScanner{}
		fetcher := NewContextFetcher(scanner, tmpDir)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidate(ctx, "not-a-valid-url")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

// TestClassifyDLPResult verifies the DLP result classification for policy input
// RFA-xwc: The policy uses classification to decide if content is too sensitive
func TestClassifyDLPResult(t *testing.T) {
	tests := []struct {
		name                   string
		result                 middleware.ScanResult
		expectedClassification string
	}{
		{
			name: "clean content",
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				HasSuspicious:  false,
			},
			expectedClassification: "clean",
		},
		{
			name: "credentials classified as sensitive",
			result: middleware.ScanResult{
				HasCredentials: true,
			},
			expectedClassification: "sensitive",
		},
		{
			name: "PII classified as sensitive",
			result: middleware.ScanResult{
				HasPII: true,
			},
			expectedClassification: "sensitive",
		},
		{
			name: "suspicious content",
			result: middleware.ScanResult{
				HasSuspicious: true,
			},
			expectedClassification: "suspicious",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyDLPResult(tt.result)
			if result != tt.expectedClassification {
				t.Errorf("expected classification %q, got %q", tt.expectedClassification, result)
			}
		})
	}
}

// TestNewContextFetcherWithPolicy verifies constructor with policy evaluator
func TestNewContextFetcherWithPolicy(t *testing.T) {
	scanner := &mockDLPScanner{}
	policyEval := &mockContextPolicyEvaluator{allow: true}
	storageDir := "/tmp/test-storage"

	fetcher := NewContextFetcherWithPolicy(scanner, storageDir, policyEval)

	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
	if fetcher.policyEval == nil {
		t.Error("policy evaluator not set")
	}
}

// TestFetchAndValidateWithPolicy tests the policy-gated context injection
// RFA-xwc: Step 7 of the mandatory validation pipeline
func TestFetchAndValidateWithPolicy(t *testing.T) {
	// Create test server serving clean content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Clean test content</body></html>"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	t.Run("policy_allows_clean_content", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		policyEval := &mockContextPolicyEvaluator{allow: true}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, &SessionFlags{
			Flags: map[string]bool{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}
		if ref.ContentID == "" {
			t.Error("content ID not set")
		}

		// Verify policy was called with correct input
		if policyEval.lastInput.Context.Source != "external" {
			t.Errorf("expected source 'external', got %q", policyEval.lastInput.Context.Source)
		}
		if !policyEval.lastInput.Context.Validated {
			t.Error("expected validated=true")
		}
		if policyEval.lastInput.Context.Classification != "clean" {
			t.Errorf("expected classification 'clean', got %q", policyEval.lastInput.Context.Classification)
		}
		if policyEval.lastInput.Context.Handle == "" {
			t.Error("expected non-empty handle")
		}
	})

	t.Run("policy_denies_returns_ContextPolicyDeniedError", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		policyEval := &mockContextPolicyEvaluator{
			allow:  false,
			reason: "context_injection_denied",
		}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, &SessionFlags{
			Flags: map[string]bool{"high_risk": true},
		})
		if err == nil {
			t.Fatal("expected error when policy denies")
		}

		// Verify the error is a ContextPolicyDeniedError
		policyErr, ok := err.(*ContextPolicyDeniedError)
		if !ok {
			t.Fatalf("expected *ContextPolicyDeniedError, got %T: %v", err, err)
		}
		if policyErr.Reason != "context_injection_denied" {
			t.Errorf("expected reason 'context_injection_denied', got %q", policyErr.Reason)
		}

		// Verify session flags were passed to policy
		if !policyEval.lastInput.Session.Flags["high_risk"] {
			t.Error("expected high_risk flag to be passed to policy")
		}
	})

	t.Run("policy_denies_sensitive_content", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         true,
				Flags:          []string{"potential_pii"},
			},
		}
		policyEval := &mockContextPolicyEvaluator{
			allow:  false,
			reason: "context_injection_denied",
		}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, &SessionFlags{
			Flags: map[string]bool{},
		})
		if err == nil {
			t.Fatal("expected error when policy denies sensitive content")
		}

		// Verify classification was set to sensitive (PII)
		if policyEval.lastInput.Context.Classification != "sensitive" {
			t.Errorf("expected classification 'sensitive', got %q", policyEval.lastInput.Context.Classification)
		}
	})

	t.Run("step_up_token_passed_to_policy", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         true,
				Flags:          []string{"potential_pii"},
			},
		}
		policyEval := &mockContextPolicyEvaluator{allow: true}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, &SessionFlags{
			Flags:       map[string]bool{},
			StepUpToken: "valid-step-up-token-123",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}

		// Verify step-up token was passed to policy
		if policyEval.lastInput.StepUpToken != "valid-step-up-token-123" {
			t.Errorf("expected step_up_token 'valid-step-up-token-123', got %q", policyEval.lastInput.StepUpToken)
		}
		// Verify classification is sensitive (PII content)
		if policyEval.lastInput.Context.Classification != "sensitive" {
			t.Errorf("expected classification 'sensitive', got %q", policyEval.lastInput.Context.Classification)
		}
	})

	t.Run("no_step_up_token_when_not_provided", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		policyEval := &mockContextPolicyEvaluator{allow: true}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, &SessionFlags{
			Flags: map[string]bool{},
			// StepUpToken intentionally omitted
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify step-up token is empty when not provided
		if policyEval.lastInput.StepUpToken != "" {
			t.Errorf("expected empty step_up_token, got %q", policyEval.lastInput.StepUpToken)
		}
	})

	t.Run("nil_session_flags_handled_gracefully", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		policyEval := &mockContextPolicyEvaluator{allow: true}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}

		// Session flags should be empty map when nil is passed
		if len(policyEval.lastInput.Session.Flags) != 0 {
			t.Error("expected empty flags map for nil session")
		}
	})

	t.Run("backward_compatible_without_policy", func(t *testing.T) {
		// FetchAndValidate (without policy) should still work when no policy evaluator is set
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		fetcher := NewContextFetcher(scanner, tmpDir) // no policy evaluator

		ctx := context.Background()
		ref, err := fetcher.FetchAndValidate(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ref == nil {
			t.Fatal("expected non-nil content ref")
		}
	})

	t.Run("policy_evaluation_error_fails_closed", func(t *testing.T) {
		scanner := &mockDLPScanner{
			result: middleware.ScanResult{
				HasCredentials: false,
				HasPII:         false,
				Flags:          []string{},
			},
		}
		policyEval := &mockContextPolicyEvaluator{
			err: fmt.Errorf("OPA engine unavailable"),
		}
		fetcher := NewContextFetcherWithPolicy(scanner, tmpDir, policyEval)

		ctx := context.Background()
		_, err := fetcher.FetchAndValidateWithPolicy(ctx, server.URL, nil)
		if err == nil {
			t.Fatal("expected error when policy evaluation fails")
		}
		if !strings.Contains(err.Error(), "context policy evaluation failed") {
			t.Errorf("expected policy evaluation failure error, got: %v", err)
		}
	})
}

// TestContextPolicyDeniedError verifies the error type
func TestContextPolicyDeniedError(t *testing.T) {
	err := &ContextPolicyDeniedError{Reason: "session_high_risk"}
	expected := "context injection denied by policy: session_high_risk"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
