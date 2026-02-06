// UI Resource Controls - RFA-j2d.2
// Content-level controls for ui:// resource reads that pass capability gating.
// Implements Reference Architecture Section 7.9.3.
//
// Controls applied in order:
//  1. Content-type validation (must be text/html;profile=mcp-app)
//  2. Size limit enforcement (default 2 MB, configurable per server/tenant)
//  3. Content scanning for dangerous patterns (UIResourceScanner)
//  4. Hash verification against cached baseline (rug-pull detection)
//
// Timeout enforcement is handled at the HTTP transport level when proxying
// the resources/read call to the upstream server.
package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"
)

// UIResourceControlResult represents the outcome of applying resource controls
// to a ui:// resource read response.
type UIResourceControlResult struct {
	Allowed  bool                      `json:"allowed"`
	Reason   string                    `json:"reason,omitempty"`
	Finding  string                    `json:"finding,omitempty"`  // e.g., "ui_dangerous_pattern", "ui_csp_violation"
	Severity string                    `json:"severity,omitempty"` // "critical", "high", "medium"
	Events   []UIResourceControlEvent  `json:"events,omitempty"`
	Findings []ScanFinding             `json:"scan_findings,omitempty"`
}

// UIResourceControlEvent is an audit event emitted by resource controls.
type UIResourceControlEvent struct {
	EventType   string `json:"event_type"`
	Server      string `json:"server"`
	Tenant      string `json:"tenant"`
	ResourceURI string `json:"resource_uri"`
	Reason      string `json:"reason"`
	Severity    string `json:"severity,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// UIResourceControls encapsulates the content-level controls for ui:// resources.
// It holds references to the UIConfig, scanner, and cache.
type UIResourceControls struct {
	config  *UIConfig
	scanner *UIResourceScanner
	cache   *UIResourceCache
}

// NewUIResourceControls creates a new UIResourceControls instance.
// The scanner and cache are created internally based on the UIConfig.
func NewUIResourceControls(config *UIConfig) *UIResourceControls {
	cacheTTL := time.Duration(config.ResourceCacheTTLSeconds) * time.Second
	return &UIResourceControls{
		config:  config,
		scanner: NewUIResourceScanner(),
		cache:   NewUIResourceCache(cacheTTL),
	}
}

// ValidateContentType checks that the content-type matches the required
// MCP Apps MIME type: text/html;profile=mcp-app.
// Returns nil if valid, an error describing the mismatch otherwise.
func ValidateContentType(contentType string) error {
	// Normalize: lowercase, strip whitespace around semicolons
	normalized := strings.ToLower(strings.TrimSpace(contentType))

	// Accept "text/html;profile=mcp-app" with optional whitespace around ";"
	// Also accept with charset parameter as long as the profile is present.
	if !strings.Contains(normalized, "text/html") {
		return fmt.Errorf("content-type must be text/html;profile=mcp-app, got %q", contentType)
	}

	if !strings.Contains(normalized, "profile=mcp-app") {
		return fmt.Errorf("content-type missing required profile=mcp-app parameter, got %q", contentType)
	}

	return nil
}

// ValidateSize checks that the content does not exceed the configured maximum size.
// maxSizeBytes is the per-server/tenant limit (from capability grant or global default).
func ValidateSize(content []byte, maxSizeBytes int64) error {
	size := int64(len(content))
	if size > maxSizeBytes {
		return fmt.Errorf("resource size %d bytes exceeds limit of %d bytes", size, maxSizeBytes)
	}
	return nil
}

// DecodeBlob decodes base64-encoded content from MCP resource blob fields.
// If the content is not base64-encoded, it is returned as-is.
// This handles the case where binary content (blob field) contains
// base64-encoded HTML that must be decoded before validation.
func DecodeBlob(content []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(content)))
	n, err := base64.StdEncoding.Decode(decoded, content)
	if err != nil {
		// Not valid base64 - return original content (may be raw HTML)
		return content, nil
	}
	return decoded[:n], nil
}

// ContentHash computes the SHA-256 hash of content, returned as a hex string.
func ContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// ApplyResourceControls runs the full set of resource controls on a ui:// resource.
// This is the main entry point for the control pipeline.
//
// Parameters:
//   - content: the raw resource content (HTML)
//   - contentType: the Content-Type header from the upstream response
//   - server: the MCP server name
//   - tenant: the tenant identifier
//   - resourceURI: the ui:// resource URI
//   - maxSizeOverride: per-server size limit (0 = use global default)
//
// Returns a UIResourceControlResult indicating whether the resource is allowed.
func (rc *UIResourceControls) ApplyResourceControls(
	content []byte,
	contentType string,
	server, tenant, resourceURI string,
	maxSizeOverride int64,
) UIResourceControlResult {

	// 1. Content-type validation
	if err := ValidateContentType(contentType); err != nil {
		return UIResourceControlResult{
			Allowed:  false,
			Reason:   "content_type_mismatch",
			Finding:  "content_type_mismatch",
			Severity: "high",
			Events: []UIResourceControlEvent{{
				EventType:   "ui.resource.blocked",
				Server:      server,
				Tenant:      tenant,
				ResourceURI: resourceURI,
				Reason:      "content_type_mismatch",
				Severity:    "high",
				Detail:      err.Error(),
			}},
		}
	}

	// 2. Size limit enforcement
	maxSize := rc.config.MaxResourceSizeBytes
	if maxSizeOverride > 0 {
		maxSize = maxSizeOverride
	}
	if err := ValidateSize(content, maxSize); err != nil {
		return UIResourceControlResult{
			Allowed:  false,
			Reason:   "size_exceeded",
			Finding:  "size_exceeded",
			Severity: "high",
			Events: []UIResourceControlEvent{{
				EventType:   "ui.resource.blocked",
				Server:      server,
				Tenant:      tenant,
				ResourceURI: resourceURI,
				Reason:      "size_exceeded",
				Severity:    "high",
				Detail:      err.Error(),
			}},
		}
	}

	// 3. Content scanning for dangerous patterns
	if rc.config.ScanEnabled {
		findings := rc.scanner.Scan(content)
		if len(findings) > 0 && rc.config.BlockOnDangerousPatterns {
			detail := fmt.Sprintf("%d dangerous pattern(s) detected", len(findings))
			if len(findings) > 0 {
				detail += fmt.Sprintf(": first match is [%s] %q at offset %d",
					findings[0].Category, findings[0].Match, findings[0].Offset)
			}
			return UIResourceControlResult{
				Allowed:  false,
				Reason:   "ui_dangerous_pattern",
				Finding:  "ui_dangerous_pattern",
				Severity: "critical",
				Findings: findings,
				Events: []UIResourceControlEvent{{
					EventType:   "ui.resource.blocked",
					Server:      server,
					Tenant:      tenant,
					ResourceURI: resourceURI,
					Reason:      "ui_dangerous_pattern",
					Severity:    "critical",
					Detail:      detail,
				}},
			}
		}
	}

	// 4. Hash verification and caching
	if rc.config.HashVerificationEnabled {
		hash := ContentHash(content)

		// Check cache for hash mismatch (rug-pull detection)
		cached := rc.cache.Get(server, resourceURI)
		if cached != nil && cached.ContentHash != hash {
			log.Printf("[CRITICAL] UI resource hash mismatch: server=%s uri=%s expected=%s got=%s",
				server, resourceURI, cached.ContentHash, hash)
			return UIResourceControlResult{
				Allowed:  false,
				Reason:   "hash_mismatch",
				Finding:  "hash_mismatch",
				Severity: "critical",
				Events: []UIResourceControlEvent{{
					EventType:   "ui.resource.hash_mismatch",
					Server:      server,
					Tenant:      tenant,
					ResourceURI: resourceURI,
					Reason:      "content_changed_after_approval",
					Severity:    "critical",
					Detail: fmt.Sprintf("expected hash %s, got %s (content changed - possible rug pull)",
						cached.ContentHash, hash),
				}},
			}
		}

		// Store/update cache entry
		rc.cache.Put(server, resourceURI, hash, content)
	}

	// All controls passed
	return UIResourceControlResult{
		Allowed: true,
	}
}

// GetCache returns the underlying resource cache for external access
// (e.g., for integration testing or metrics).
func (rc *UIResourceControls) GetCache() *UIResourceCache {
	return rc.cache
}

// GetScanner returns the underlying scanner for external access.
func (rc *UIResourceControls) GetScanner() *UIResourceScanner {
	return rc.scanner
}

// Close cleans up resources held by the controls (cache cleanup goroutine).
func (rc *UIResourceControls) Close() {
	if rc.cache != nil {
		rc.cache.Close()
	}
}

// FetchTimeout returns the configured fetch timeout as a time.Duration.
// This is used by the proxy handler to set the upstream request deadline.
func (rc *UIResourceControls) FetchTimeout() time.Duration {
	return time.Duration(rc.config.ResourceFetchTimeoutSeconds) * time.Second
}
