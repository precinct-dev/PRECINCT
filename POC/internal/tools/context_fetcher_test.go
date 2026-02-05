package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// mockDLPScanner for testing
type mockDLPScanner struct {
	result middleware.ScanResult
}

func (m *mockDLPScanner) Scan(content string) middleware.ScanResult {
	return m.result
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
