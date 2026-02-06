package middleware

import (
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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

// piiCheckFunc is a custom PII detection function for patterns that need
// validation beyond simple regex (e.g., checksum verification, context-aware matching).
// Returns true if PII is detected in the content.
type piiCheckFunc func(content string) bool

// BuiltInScanner is a regex-based DLP scanner implementation
type BuiltInScanner struct {
	credentialPatterns []*regexp.Regexp
	piiPatterns        []*regexp.Regexp
	customPIIChecks    []piiCheckFunc
	suspiciousPatterns []*regexp.Regexp
}

// NewBuiltInScanner creates a new built-in DLP scanner
func NewBuiltInScanner() *BuiltInScanner {
	return &BuiltInScanner{
		credentialPatterns: []*regexp.Regexp{
			// API keys and tokens
			regexp.MustCompile(`\bsk-proj-[a-zA-Z0-9]{20,}\b`),                              // OpenAI project keys
			regexp.MustCompile(`\bsk-[a-zA-Z0-9]{32,}\b`),                                   // OpenAI keys
			regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                      // AWS access keys
			regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36,}\b`),                                  // GitHub personal access tokens
			regexp.MustCompile(`\bgho_[a-zA-Z0-9]{36,}\b`),                                  // GitHub OAuth tokens
			regexp.MustCompile(`\bghs_[a-zA-Z0-9]{36,}\b`),                                  // GitHub server-to-server tokens
			regexp.MustCompile(`\bghr_[a-zA-Z0-9]{36,}\b`),                                  // GitHub refresh tokens
			regexp.MustCompile(`\bglpat-[a-zA-Z0-9_\-]{20,}\b`),                             // GitLab personal access tokens
			regexp.MustCompile(`\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b`), // Slack tokens
			regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),                       // Private keys

			// Obvious credential patterns in key=value format or JSON
			regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*[^\s]{8,}`),
			regexp.MustCompile(`(?i)\bsecret\s*[:=]\s*[^\s]{8,}`),
			regexp.MustCompile(`(?i)\btoken\s*[:=]\s*[^\s]{16,}`),
			regexp.MustCompile(`(?i)["']?api[_-]?key["']?\s*[":=]\s*["']?[a-zA-Z0-9]{8,}`),
			regexp.MustCompile(`(?i)\baccess[_-]?key\s*[:=]\s*[^\s]{16,}`),
			// Generic API key pattern (from SafeZone)
			regexp.MustCompile(`\b(api_key|apikey|access_token|auth_token)\s*[:=]\s*[A-Za-z0-9\-_]{16,64}\b`),
		},
		piiPatterns: []*regexp.Regexp{
			// SSN patterns (XXX-XX-XXXX)
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			// Email addresses
			regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			// Phone numbers (various formats)
			regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
			regexp.MustCompile(`\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b`),
			// International phone numbers (from SafeZone)
			regexp.MustCompile(`\+(?:[0-9] ?){6,14}[0-9]`),
			// Credit card numbers (simple pattern)
			regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
			// UK National Insurance Number (from SafeZone)
			regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b`),
			// MAC Address (from SafeZone)
			regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b`),
			// UUID/GUID pattern (from SafeZone)
			regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
			// Generic IBAN pattern (EU format, from SafeZone)
			regexp.MustCompile(`\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?(?:[\dA-Z]{4}\s?){2,7}[\dA-Z]{1,4}\b`),
			// Date-of-birth pattern (DD/MM/YYYY, DD-MM-YYYY, DD.MM.YYYY, from SafeZone)
			regexp.MustCompile(`\b\d{2}[./-]\d{2}[./-]\d{4}\b`),
			// US Employer Identification Number (XX-XXXXXXX)
			regexp.MustCompile(`\b\d{2}-\d{7}\b`),
			// US Individual Taxpayer Identification Number (9XX-[7-9]X-XXXX)
			regexp.MustCompile(`\b9\d{2}-[7-9]\d-\d{4}\b`),
			// US Passport Number (letter + 8 digits)
			regexp.MustCompile(`\b[A-Z]\d{8}\b`),
			// US Medicare Beneficiary Identifier (MBI)
			// Format: C[AN][AN]N[A][AN]N[AA]NN where C=1-9, A=alpha(no S,L,O,I,B,Z),
			// N=numeric, AN=alpha-or-numeric (same exclusions)
			regexp.MustCompile(`\b[1-9][AC-HJKMNP-RT][AC-HJKMNP-RT0-9]\d[AC-HJKMNP-RT][AC-HJKMNP-RT0-9]\d[AC-HJKMNP-RT]{2}\d{2}\b`),
		},
		customPIIChecks: []piiCheckFunc{
			// US Bank Routing Number: 9 digits with ABA checksum, context-aware
			checkABARoutingNumber,
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
			// DAN jailbreak pattern (from SafeZone)
			regexp.MustCompile(`(?i)(DAN mode|do anything now)`),
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

	// Check for PII (regex patterns)
	for _, pattern := range s.piiPatterns {
		if pattern.MatchString(content) {
			result.HasPII = true
			if !contains(result.Flags, "potential_pii") {
				result.Flags = append(result.Flags, "potential_pii")
			}
		}
	}

	// Check for PII (custom validation checks, e.g., checksum-based)
	for _, check := range s.customPIIChecks {
		if check(content) {
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

// abaRoutingPattern matches 9-digit sequences that could be routing numbers.
var abaRoutingPattern = regexp.MustCompile(`\b\d{9}\b`)

// abaContextPattern matches keywords that suggest the nearby number is a routing number.
// Case-insensitive matching is done by lowercasing the content before checking.
var abaContextKeywords = []string{
	"routing", "aba", "rtn", "bank", "transit",
}

// checkABARoutingNumber detects US bank routing numbers using context-aware matching.
// A 9-digit number is flagged only if it passes the ABA checksum AND appears near
// a contextual keyword (within 50 characters), reducing false positives.
func checkABARoutingNumber(content string) bool {
	matches := abaRoutingPattern.FindAllStringIndex(content, -1)
	if len(matches) == 0 {
		return false
	}
	lower := strings.ToLower(content)
	for _, loc := range matches {
		candidate := content[loc[0]:loc[1]]
		if !ValidateABAChecksum(candidate) {
			continue
		}
		// Check for contextual keywords within 50 chars before or after the match
		contextStart := loc[0] - 50
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := loc[1] + 50
		if contextEnd > len(lower) {
			contextEnd = len(lower)
		}
		surrounding := lower[contextStart:contextEnd]
		for _, kw := range abaContextKeywords {
			if strings.Contains(surrounding, kw) {
				return true
			}
		}
	}
	return false
}

// ValidateABAChecksum verifies the ABA routing number checksum.
// The algorithm: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) must be divisible by 10.
// Input must be exactly 9 ASCII digits.
func ValidateABAChecksum(number string) bool {
	if len(number) != 9 {
		return false
	}
	for _, c := range number {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	d := make([]int, 9)
	for i, c := range number {
		d[i] = int(c - '0')
	}
	checksum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return checksum%10 == 0
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
		// RFA-m6j.2: Create OTel span for step 7
		ctx, span := tracer.Start(r.Context(), "gateway.dlp_scan",
			trace.WithAttributes(
				attribute.Int("mcp.gateway.step", 7),
				attribute.String("mcp.gateway.middleware", "dlp_scan"),
			),
		)
		defer span.End()

		// Get captured request body from context
		body := GetRequestBody(ctx)

		if body == nil {
			// No body to scan, continue
			span.SetAttributes(
				attribute.Bool("has_credentials", false),
				attribute.Bool("has_pii", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "no body"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Scan the request body
		result := scanner.Scan(string(body))

		// Handle scanner errors - fail open
		if result.Error != nil {
			// Log error but allow request to continue
			span.SetAttributes(
				attribute.Bool("has_credentials", false),
				attribute.Bool("has_pii", false),
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "scanner error - fail open"),
			)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// RFA-m6j.2: Set DLP scan span attributes
		span.SetAttributes(
			attribute.Bool("has_credentials", result.HasCredentials),
			attribute.Bool("has_pii", result.HasPII),
			attribute.StringSlice("flags", result.Flags),
		)

		// FAIL CLOSED: Block requests with credentials
		if result.HasCredentials {
			// Add flags to context for audit logging
			ctx = WithSecurityFlags(ctx, result.Flags)

			span.SetAttributes(
				attribute.String("mcp.result", "denied"),
				attribute.String("mcp.reason", "credentials detected"),
			)
			http.Error(w, "Forbidden: Request contains sensitive credentials", http.StatusForbidden)
			return
		}

		// Determine result for span
		if result.HasPII || result.HasSuspicious {
			span.SetAttributes(
				attribute.String("mcp.result", "flagged"),
				attribute.String("mcp.reason", strings.Join(result.Flags, ",")),
			)
		} else {
			span.SetAttributes(
				attribute.String("mcp.result", "allowed"),
				attribute.String("mcp.reason", "clean"),
			)
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
