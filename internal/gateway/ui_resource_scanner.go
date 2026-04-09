// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// UIResourceScanner - RFA-j2d.2
// Static analysis scanner for MCP-UI (ui://) HTML+JS resource content.
// Detects dangerous patterns that could indicate active exploits, sandbox
// breakout attempts, or data exfiltration in MCP App UI resources.
//
// Reference Architecture Section 7.9.3: Content scanning.
//
// The scanner uses regexp-based pattern matching across seven categories:
//  1. Script injection via event handlers
//  2. Parent/top frame access
//  3. Dynamic script creation
//  4. Sandbox breakout
//  5. External resource loading
//  6. WebRTC exfiltration
//  7. Service workers
//
// Each finding includes the category, matched pattern, and byte offset
// to support audit logging and incident response.
package gateway

import (
	"fmt"
	"regexp"
)

// ScanFindingCategory enumerates the categories of dangerous patterns.
type ScanFindingCategory string

const (
	// CategoryEventHandler detects inline event handler attributes (onclick, onerror, etc.)
	// that can execute arbitrary JavaScript when triggered by DOM events.
	CategoryEventHandler ScanFindingCategory = "event_handler_injection"

	// CategoryFrameAccess detects attempts to access parent, top, or opener frames,
	// which can break out of sandboxed iframes.
	CategoryFrameAccess ScanFindingCategory = "parent_top_frame_access"

	// CategoryDynamicScript detects dynamic script creation via document.write,
	// eval(), or the Function constructor, which bypass static CSP analysis.
	CategoryDynamicScript ScanFindingCategory = "dynamic_script_creation"

	// CategorySandboxBreakout detects attempts to manipulate the window location,
	// open new windows, or access cookies from within a sandboxed context.
	CategorySandboxBreakout ScanFindingCategory = "sandbox_breakout"

	// CategoryExternalResource detects external resource loading via script, link,
	// or iframe tags with absolute HTTP(S) src attributes.
	CategoryExternalResource ScanFindingCategory = "external_resource_loading"

	// CategoryWebRTC detects WebRTC API usage (RTCPeerConnection, RTCDataChannel)
	// which can establish direct peer-to-peer connections for data exfiltration.
	CategoryWebRTC ScanFindingCategory = "webrtc_exfiltration"

	// CategoryServiceWorker detects service worker registration attempts, which
	// can intercept network requests and persist beyond the page lifecycle.
	CategoryServiceWorker ScanFindingCategory = "service_worker"
)

// ScanFinding represents a single dangerous pattern match in scanned content.
type ScanFinding struct {
	Category ScanFindingCategory `json:"category"`
	Pattern  string              `json:"pattern"` // The regexp pattern that matched
	Match    string              `json:"match"`   // The actual text that matched
	Offset   int                 `json:"offset"`  // Byte offset in the content
}

// String returns a human-readable description of the finding.
func (f ScanFinding) String() string {
	return fmt.Sprintf("[%s] matched %q at offset %d", f.Category, f.Match, f.Offset)
}

// dangerousPattern pairs a compiled regexp with its category for scanning.
type dangerousPattern struct {
	category ScanFindingCategory
	re       *regexp.Regexp
	source   string // original pattern string for reporting
}

// UIResourceScanner performs static analysis on HTML+JS content to detect
// dangerous patterns. It is safe for concurrent use.
type UIResourceScanner struct {
	patterns []dangerousPattern
}

// NewUIResourceScanner creates a scanner with the standard set of dangerous
// patterns as defined in Reference Architecture Section 7.9.3.
func NewUIResourceScanner() *UIResourceScanner {
	// Pattern definitions. All regexps use (?i) for case-insensitive matching
	// since HTML/JS is case-insensitive for attributes and some APIs.
	patternDefs := []struct {
		category ScanFindingCategory
		pattern  string
	}{
		// 1. Script injection via event handlers
		{CategoryEventHandler, `(?i)on(error|load|click|mouse\w*|key\w*|focus|blur)\s*=`},

		// 2. Parent/top frame access
		{CategoryFrameAccess, `(?i)(parent|top|opener)\.(location|document|postMessage)`},

		// 3. Dynamic script creation
		{CategoryDynamicScript, `(?i)(document\.write|eval\s*\(|Function\s*\()`},

		// 4. Sandbox breakout
		{CategorySandboxBreakout, `(?i)(window\.(open|location)|document\.cookie)`},

		// 5. External resource loading (script/link/iframe with http(s):// src)
		{CategoryExternalResource, `(?i)<(script|link|iframe)\s+[^>]*src\s*=\s*["']https?://`},

		// 6. WebRTC exfiltration
		{CategoryWebRTC, `(?i)(RTCPeerConnection|RTCDataChannel)`},

		// 7. Service workers
		{CategoryServiceWorker, `(?i)(serviceWorker\.register|navigator\.serviceWorker)`},
	}

	scanner := &UIResourceScanner{
		patterns: make([]dangerousPattern, 0, len(patternDefs)),
	}

	for _, pd := range patternDefs {
		scanner.patterns = append(scanner.patterns, dangerousPattern{
			category: pd.category,
			re:       regexp.MustCompile(pd.pattern),
			source:   pd.pattern,
		})
	}

	return scanner
}

// Scan analyzes HTML content for dangerous patterns and returns all findings.
// An empty slice indicates the content passed scanning with no issues.
func (s *UIResourceScanner) Scan(content []byte) []ScanFinding {
	var findings []ScanFinding

	for _, p := range s.patterns {
		matches := p.re.FindAllIndex(content, -1)
		for _, loc := range matches {
			matchText := string(content[loc[0]:loc[1]])
			findings = append(findings, ScanFinding{
				Category: p.category,
				Pattern:  p.source,
				Match:    matchText,
				Offset:   loc[0],
			})
		}
	}

	return findings
}

// ScanString is a convenience method that scans a string instead of bytes.
func (s *UIResourceScanner) ScanString(content string) []ScanFinding {
	return s.Scan([]byte(content))
}

// HasDangerousPatterns returns true if any dangerous patterns are found.
// This is a convenience method for quick pass/fail checks.
func (s *UIResourceScanner) HasDangerousPatterns(content []byte) bool {
	for _, p := range s.patterns {
		if p.re.Match(content) {
			return true
		}
	}
	return false
}

// PatternCount returns the number of pattern categories the scanner checks.
func (s *UIResourceScanner) PatternCount() int {
	return len(s.patterns)
}
