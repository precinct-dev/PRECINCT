package middleware

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// DLPScanner defines the interface for data loss prevention scanning
// This allows swapping in SafeZone or other implementations later
type DLPScanner interface {
	Scan(content string) ScanResult
}

// ScanResult contains the results of a DLP scan
type ScanResult struct {
	HasCredentials bool
	HasPII         bool
	HasSuspicious  bool
	Flags          []string
	Error          error
}

// BuiltInScanner is a regex-based DLP scanner implementation
type BuiltInScanner struct {
	credentialPatterns []*regexp.Regexp
	piiPatterns        []*regexp.Regexp
	suspiciousPatterns []*regexp.Regexp
}

// NewBuiltInScanner creates a new built-in DLP scanner
func NewBuiltInScanner() *BuiltInScanner {
	return &BuiltInScanner{
		credentialPatterns: []*regexp.Regexp{
			// API keys and tokens
			regexp.MustCompile(`\bsk-proj-[a-zA-Z0-9]{20,}\b`),                // OpenAI project keys
			regexp.MustCompile(`\bsk-[a-zA-Z0-9]{32,}\b`),                     // OpenAI keys
			regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                        // AWS access keys
			regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36,}\b`),                    // GitHub personal access tokens
			regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36,}\b`),                    // GitHub OAuth tokens
			regexp.MustCompile(`\bghs_[a-zA-Z0-9]{36,}\b`),                    // GitHub server-to-server tokens
			regexp.MustCompile(`\bghr_[a-zA-Z0-9]{36,}\b`),                    // GitHub refresh tokens
			regexp.MustCompile(`\bglpat-[a-zA-Z0-9_\-]{20,}\b`),               // GitLab personal access tokens
			regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b`), // Slack tokens
			regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),         // Private keys

			// Obvious credential patterns in key=value format or JSON
			regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*[^\s]{8,}`),
			regexp.MustCompile(`(?i)\bsecret\s*[:=]\s*[^\s]{8,}`),
			regexp.MustCompile(`(?i)\btoken\s*[:=]\s*[^\s]{16,}`),
			regexp.MustCompile(`(?i)["']?api[_-]?key["']?\s*[":=]\s*["']?[a-zA-Z0-9]{8,}`),
			regexp.MustCompile(`(?i)\baccess[_-]?key\s*[:=]\s*[^\s]{16,}`),
		},
		piiPatterns: []*regexp.Regexp{
			// SSN patterns (XXX-XX-XXXX)
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			// Email addresses
			regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			// Phone numbers (various formats)
			regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
			regexp.MustCompile(`\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b`),
			// Credit card numbers (simple pattern)
			regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
		},
		suspiciousPatterns: []*regexp.Regexp{
			// SQL injection patterns
			regexp.MustCompile(`(?i)\b(union\s+(all\s+)?select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|exec\s+|execute\s+)`),
			regexp.MustCompile(`(?i)[';]--`),
			regexp.MustCompile(`(?i)\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),

			// Prompt injection patterns
			regexp.MustCompile(`(?i)ignore\s+(all|previous|your)\s+(previous\s+)?(instructions|rules|prompts?)`),
			regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
			regexp.MustCompile(`(?i)forget\s+(everything|all|your\s+instructions)`),
			regexp.MustCompile(`(?i)disregard\s+(previous|all|your)\s+(instructions|rules)`),
			regexp.MustCompile(`(?i)new\s+instructions?\s*:`),
		},
	}
}

// Scan performs DLP scanning on the given content
func (s *BuiltInScanner) Scan(content string) ScanResult {
	result := ScanResult{
		Flags: make([]string, 0),
	}

	// Check for credentials
	for _, pattern := range s.credentialPatterns {
		if pattern.MatchString(content) {
			result.HasCredentials = true
			result.Flags = append(result.Flags, "blocked_content")
			break
		}
	}

	// Check for PII
	for _, pattern := range s.piiPatterns {
		if pattern.MatchString(content) {
			result.HasPII = true
			if !contains(result.Flags, "potential_pii") {
				result.Flags = append(result.Flags, "potential_pii")
			}
		}
	}

	// Check for suspicious content
	for _, pattern := range s.suspiciousPatterns {
		if pattern.MatchString(content) {
			result.HasSuspicious = true
			if !contains(result.Flags, "potential_injection") {
				result.Flags = append(result.Flags, "potential_injection")
			}
		}
	}

	return result
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// DLPMiddleware creates middleware for DLP scanning
// Position: After OPA policy, before session context
func DLPMiddleware(next http.Handler, scanner DLPScanner) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get captured request body from context
		ctx := r.Context()
		body := GetRequestBody(ctx)

		if body == nil {
			// No body to scan, continue
			next.ServeHTTP(w, r)
			return
		}

		// Scan the request body
		result := scanner.Scan(string(body))

		// Handle scanner errors - fail open
		if result.Error != nil {
			// Log error but allow request to continue
			// In production, this might be logged to a monitoring system
			next.ServeHTTP(w, r)
			return
		}

		// FAIL CLOSED: Block requests with credentials
		if result.HasCredentials {
			// Add flags to context for audit logging
			ctx = WithSecurityFlags(ctx, result.Flags)

			http.Error(w, "Forbidden: Request contains sensitive credentials", http.StatusForbidden)
			return
		}

		// Add security flags to context for audit logging
		// PII and suspicious content are flagged but NOT blocked
		if len(result.Flags) > 0 {
			ctx = WithSecurityFlags(ctx, result.Flags)
		}

		// Continue with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Security flags context key
const contextKeySecurityFlags contextKey = "security_flags"

// WithSecurityFlags adds security flags to context
func WithSecurityFlags(ctx context.Context, flags []string) context.Context {
	return context.WithValue(ctx, contextKeySecurityFlags, flags)
}

// GetSecurityFlags retrieves security flags from context
func GetSecurityFlags(ctx context.Context) []string {
	if v := ctx.Value(contextKeySecurityFlags); v != nil {
		return v.([]string)
	}
	return nil
}

// FormatSecurityFlags formats security flags for logging
func FormatSecurityFlags(flags []string) string {
	if len(flags) == 0 {
		return ""
	}
	return strings.Join(flags, ",")
}

// ScanError creates a scan result with an error
func ScanError(err error) ScanResult {
	return ScanResult{
		Error: err,
	}
}
