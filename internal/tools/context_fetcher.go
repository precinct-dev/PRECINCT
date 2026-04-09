// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/google/uuid"
)

const (
	// MaxContentSize limits the size of fetched content (10MB)
	MaxContentSize = 10 * 1024 * 1024
	// ChunkSize defines the size of content chunks (4KB)
	ChunkSize = 4 * 1024
	// FetchTimeout defines the maximum time to wait for content fetch
	FetchTimeout = 30 * time.Second
)

// ContentRef represents a reference to stored, validated content
type ContentRef struct {
	ContentID  string             `json:"content_id"`
	Provenance ProvenanceMetadata `json:"provenance"`
	ChunkCount int                `json:"chunk_count"`
	DLPFlags   []string           `json:"dlp_flags,omitempty"`
}

// ProvenanceMetadata tracks the origin and validation of content
type ProvenanceMetadata struct {
	SourceURL     string    `json:"source_url"`
	FetchTime     time.Time `json:"fetch_time"`
	ContentHash   string    `json:"content_hash"`
	ContentLength int       `json:"content_length"`
	DLPScanned    bool      `json:"dlp_scanned"`
	DLPResult     string    `json:"dlp_result,omitempty"`
}

// ContextFetcher handles external content ingestion with validation
type ContextFetcher struct {
	scanner    middleware.DLPScanner
	policyEval middleware.ContextPolicyEvaluator // RFA-xwc: OPA policy gate (step 7)
	storageDir string
	httpClient *http.Client
}

// NewContextFetcher creates a new context fetcher instance
func NewContextFetcher(scanner middleware.DLPScanner, storageDir string) *ContextFetcher {
	return &ContextFetcher{
		scanner:    scanner,
		storageDir: storageDir,
		httpClient: &http.Client{
			Timeout: FetchTimeout,
			// Sandboxed: no custom transport, no proxy settings that could leak env
		},
	}
}

// NewContextFetcherWithPolicy creates a context fetcher with OPA policy evaluation
// RFA-xwc: Step 7 of the mandatory validation pipeline (Section 10.15.1)
func NewContextFetcherWithPolicy(scanner middleware.DLPScanner, storageDir string, policyEval middleware.ContextPolicyEvaluator) *ContextFetcher {
	cf := NewContextFetcher(scanner, storageDir)
	cf.policyEval = policyEval
	return cf
}

// SessionFlags carries session-level flags for policy evaluation
// RFA-xwc: Used to pass session context into the policy gate
type SessionFlags struct {
	Flags       map[string]bool
	StepUpToken string // Non-empty when step-up approval was obtained for sensitive content
}

// ContextPolicyDeniedError represents a denial from the OPA context injection policy
// RFA-xwc: HTTP handlers can type-assert this to return 403
type ContextPolicyDeniedError struct {
	Reason string
}

func (e *ContextPolicyDeniedError) Error() string {
	return fmt.Sprintf("context injection denied by policy: %s", e.Reason)
}

// FetchAndValidate fetches external content, validates it, and returns a content reference
// This runs in a sandboxed context with no access to environment secrets.
// For policy-gated context injection, use FetchAndValidateWithPolicy instead.
func (cf *ContextFetcher) FetchAndValidate(ctx context.Context, sourceURL string) (*ContentRef, error) {
	return cf.fetchAndValidateInternal(ctx, sourceURL, nil)
}

// FetchAndValidateWithPolicy fetches external content, validates it through the 7-stage
// validation pipeline including the OPA policy gate (step 7), and returns a content reference.
// RFA-xwc: Step 7 of the mandatory validation pipeline (Section 10.15.1)
// If the policy denies injection, returns a *ContextPolicyDeniedError.
func (cf *ContextFetcher) FetchAndValidateWithPolicy(ctx context.Context, sourceURL string, sessionFlags *SessionFlags) (*ContentRef, error) {
	return cf.fetchAndValidateInternal(ctx, sourceURL, sessionFlags)
}

// fetchAndValidateInternal is the shared implementation for FetchAndValidate and FetchAndValidateWithPolicy
func (cf *ContextFetcher) fetchAndValidateInternal(ctx context.Context, sourceURL string, sessionFlags *SessionFlags) (*ContentRef, error) {
	// Validate URL format
	if !isValidURL(sourceURL) {
		return nil, fmt.Errorf("invalid URL format: %s", sourceURL)
	}

	// Fetch content with timeout context
	fetchCtx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	content, err := cf.fetchContent(fetchCtx, sourceURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch content: %w", err)
	}

	// Normalize content (strip HTML, extract text)
	normalized := normalizeContent(content)

	// Chunk content
	chunks := chunkContent(normalized, ChunkSize)

	// Run DLP classification on full normalized content
	dlpResult := cf.scanner.Scan(normalized)
	if dlpResult.Error != nil {
		return nil, fmt.Errorf("DLP scan failed: %w", dlpResult.Error)
	}

	// FAIL CLOSED: Block content with credentials
	if dlpResult.HasCredentials {
		return nil, fmt.Errorf("forbidden: content contains sensitive credentials")
	}

	// Generate content ID
	contentID := uuid.New().String()

	// Calculate content hash for integrity
	hash := sha256.Sum256([]byte(normalized))
	contentHash := hex.EncodeToString(hash[:])

	// Store chunks and metadata (step 6: Storage as handle)
	if err := cf.storeContent(contentID, chunks); err != nil {
		return nil, fmt.Errorf("failed to store content: %w", err)
	}

	// RFA-xwc: Step 7 -- OPA policy gate for context injection
	// Evaluate AFTER storing content as handle but BEFORE returning the handle.
	// This ensures the policy decision happens on validated, stored content.
	if cf.policyEval != nil {
		classification := classifyDLPResult(dlpResult)

		// Build session flags for policy input
		flags := make(map[string]bool)
		stepUpToken := ""
		if sessionFlags != nil {
			if sessionFlags.Flags != nil {
				flags = sessionFlags.Flags
			}
			stepUpToken = sessionFlags.StepUpToken
		}

		policyInput := middleware.ContextPolicyInput{
			Context: middleware.ContextInput{
				Source:         "external",
				Validated:      true, // steps 1-6 all passed if we reached here
				Classification: classification,
				Handle:         contentID,
			},
			Session: middleware.ContextSessionInput{
				Flags: flags,
			},
			StepUpToken: stepUpToken,
		}

		allowed, reason, err := cf.policyEval.EvaluateContextPolicy(policyInput)
		if err != nil {
			// Fail closed on policy evaluation error
			return nil, fmt.Errorf("context policy evaluation failed: %w", err)
		}

		if !allowed {
			return nil, &ContextPolicyDeniedError{Reason: reason}
		}
	}

	// Build provenance metadata
	provenance := ProvenanceMetadata{
		SourceURL:     sourceURL,
		FetchTime:     time.Now().UTC(),
		ContentHash:   contentHash,
		ContentLength: len(normalized),
		DLPScanned:    true,
		DLPResult:     formatDLPResult(dlpResult),
	}

	// Create content reference
	ref := &ContentRef{
		ContentID:  contentID,
		Provenance: provenance,
		ChunkCount: len(chunks),
		DLPFlags:   dlpResult.Flags,
	}

	return ref, nil
}

// classifyDLPResult maps DLP scan results to a classification string for policy evaluation.
// RFA-xwc: The policy uses classification to decide if content is too sensitive for injection.
func classifyDLPResult(result middleware.ScanResult) string {
	if result.HasCredentials {
		return "sensitive" // credentials are always sensitive
	}
	if result.HasPII {
		return "sensitive" // PII is classified as sensitive for policy purposes
	}
	if result.HasSuspicious {
		return "suspicious"
	}
	return "clean"
}

// fetchContent fetches content from the given URL
// Sandboxed: no environment variables, no credential access
func (cf *ContextFetcher) fetchContent(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// Set a standard user agent, no auth headers
	req.Header.Set("User-Agent", "agentic-security-poc/1.0")

	resp, err := cf.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Limit content size
	limitedReader := io.LimitReader(resp.Body, MaxContentSize)
	contentBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", err
	}

	return string(contentBytes), nil
}

// storeContent stores content chunks to the filesystem
func (cf *ContextFetcher) storeContent(contentID string, chunks []string) error {
	// Create directory for this content
	contentDir := filepath.Join(cf.storageDir, contentID)
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return err
	}

	// Store each chunk
	for i, chunk := range chunks {
		chunkFile := filepath.Join(contentDir, fmt.Sprintf("chunk_%d.txt", i))
		if err := os.WriteFile(chunkFile, []byte(chunk), 0644); err != nil {
			return err
		}
	}

	// Store metadata
	metadata := map[string]interface{}{
		"content_id":  contentID,
		"chunk_count": len(chunks),
		"stored_at":   time.Now().UTC().Format(time.RFC3339),
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	metadataFile := filepath.Join(contentDir, "metadata.json")
	return os.WriteFile(metadataFile, metadataBytes, 0644)
}

// GetContent retrieves stored content by content_ref.
// The contentID is validated to prevent path traversal attacks.
func (cf *ContextFetcher) GetContent(contentID string) (string, error) {
	// Defense-in-depth: reject contentIDs containing path separators or
	// parent-directory references to prevent path traversal, even though
	// contentIDs are internally generated UUIDs.
	if strings.Contains(contentID, "/") || strings.Contains(contentID, "\\") || strings.Contains(contentID, "..") || contentID == "" {
		return "", fmt.Errorf("invalid content ID: %s", contentID)
	}
	contentDir := filepath.Join(cf.storageDir, contentID)

	// Read metadata to get chunk count
	metadataFile := filepath.Join(contentDir, "metadata.json")
	metadataBytes, err := os.ReadFile(metadataFile)
	if err != nil {
		return "", fmt.Errorf("content not found: %s", contentID)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", err
	}

	chunkCount := int(metadata["chunk_count"].(float64))

	// Read all chunks
	var content strings.Builder
	for i := 0; i < chunkCount; i++ {
		chunkFile := filepath.Join(contentDir, fmt.Sprintf("chunk_%d.txt", i))
		chunkBytes, err := os.ReadFile(chunkFile)
		if err != nil {
			return "", err
		}
		content.Write(chunkBytes)
	}

	return content.String(), nil
}

// normalizeContent strips HTML tags and extracts text
func normalizeContent(content string) string {
	// Strip HTML tags using regex
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	text := htmlTagRegex.ReplaceAllString(content, " ")

	// Collapse multiple whitespace
	whitespaceRegex := regexp.MustCompile(`\s+`)
	text = whitespaceRegex.ReplaceAllString(text, " ")

	// Trim leading/trailing whitespace
	text = strings.TrimSpace(text)

	return text
}

// chunkContent splits content into chunks of specified size
func chunkContent(content string, chunkSize int) []string {
	var chunks []string

	for i := 0; i < len(content); i += chunkSize {
		end := i + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunks = append(chunks, content[i:end])
	}

	return chunks
}

// isValidURL validates URL format (basic check)
func isValidURL(urlStr string) bool {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return false
	}
	return len(urlStr) > 8 // Minimum valid URL length
}

// formatDLPResult formats DLP scan result for logging
func formatDLPResult(result middleware.ScanResult) string {
	var flags []string
	if result.HasCredentials {
		flags = append(flags, "credentials")
	}
	if result.HasPII {
		flags = append(flags, "pii")
	}
	if result.HasSuspicious {
		flags = append(flags, "suspicious")
	}
	if len(flags) == 0 {
		return "clean"
	}
	return strings.Join(flags, ",")
}
