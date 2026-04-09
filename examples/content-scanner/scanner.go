// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Package main provides a content-scanner sidecar service that validates content
// through pluggable scanner implementations for the PRECINCT gateway extension slot system.
package main

import (
	"context"
	"regexp"
	"strings"
)

// Scanner defines the pluggable interface for content scanning implementations.
type Scanner interface {
	Scan(ctx context.Context, content []byte, metadata ScanMetadata) (ScanResult, error)
}

// ScanMetadata carries contextual information about the request being scanned.
type ScanMetadata struct {
	Method   string
	ToolName string
	SPIFFEID string
}

// ScanResult holds the outcome of a content scan.
type ScanResult struct {
	Decision string   // "allow", "block", "flag"
	Flags    []string
	Reason   string
	Threats  []Threat
}

// Threat represents a single detected threat within scanned content.
type Threat struct {
	Category string // "prompt_injection", "dangerous_code", "credential_leak"
	Severity string // "critical", "high", "medium", "low"
	Pattern  string
	Location string
}

// patternDef ties a compiled regex to its threat metadata.
type patternDef struct {
	regex    *regexp.Regexp
	category string
	severity string
	name     string
}

// PatternScanner is the default Scanner implementation that uses compiled regex
// patterns to detect prompt injections, dangerous code, and credential leaks.
type PatternScanner struct {
	patterns []patternDef
}

// NewPatternScanner creates a PatternScanner with all detection patterns compiled at init time.
func NewPatternScanner() *PatternScanner {
	return &PatternScanner{
		patterns: []patternDef{
			// Prompt injection -- critical
			{
				regex:    regexp.MustCompile(`(?i)<script[^>]*>`),
				category: "prompt_injection",
				severity: "critical",
				name:     "script tag injection",
			},
			{
				regex:    regexp.MustCompile(`(?i)javascript:`),
				category: "prompt_injection",
				severity: "critical",
				name:     "JS protocol handler",
			},
			// Prompt injection -- high
			{
				regex:    regexp.MustCompile(`(?i)\bignore\s+(previous|above|all)\s+instructions?\b`),
				category: "prompt_injection",
				severity: "high",
				name:     "instruction override",
			},
			{
				regex:    regexp.MustCompile(`(?i)\bsystem\s*:\s*`),
				category: "prompt_injection",
				severity: "high",
				name:     "system prompt injection",
			},
			{
				regex:    regexp.MustCompile(`(?i)\byou\s+are\s+now\b.*\bassistant\b`),
				category: "prompt_injection",
				severity: "high",
				name:     "role hijacking",
			},
			// Dangerous code -- medium
			{
				regex:    regexp.MustCompile(`(?i)\bcurl\b.*\|\s*\b(sh|bash)\b`),
				category: "dangerous_code",
				severity: "medium",
				name:     "remote code execution",
			},
			{
				regex:    regexp.MustCompile(`(?i)\beval\b\s*\(`),
				category: "dangerous_code",
				severity: "medium",
				name:     "eval execution",
			},
			{
				regex:    regexp.MustCompile(`(?i)\brm\s+-rf\b`),
				category: "dangerous_code",
				severity: "medium",
				name:     "destructive commands",
			},
			{
				regex:    regexp.MustCompile(`(?i)\bchmod\s+777\b`),
				category: "dangerous_code",
				severity: "medium",
				name:     "permission escalation",
			},
			// Credential patterns -- high
			{
				regex:    regexp.MustCompile(`(?i)(?:api[_-]?key|secret[_-]?key|password)\s*[:=]\s*['"][^'"]{8,}`),
				category: "credential_leak",
				severity: "high",
				name:     "hardcoded credentials",
			},
			{
				regex:    regexp.MustCompile(`(?:AKIA|ABIA|ACCA|AROA)[0-9A-Z]{16}`),
				category: "credential_leak",
				severity: "high",
				name:     "AWS access key ID",
			},
			{
				regex:    regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
				category: "credential_leak",
				severity: "high",
				name:     "GitHub personal access token",
			},
		},
	}
}

// PatternCount returns the number of compiled detection patterns.
func (ps *PatternScanner) PatternCount() int {
	return len(ps.patterns)
}

// Scan checks content against all compiled patterns and returns an aggregated result.
// Decision logic: any critical or high severity threat -> "block";
// any medium severity threat -> "flag"; otherwise -> "allow".
func (ps *PatternScanner) Scan(_ context.Context, content []byte, _ ScanMetadata) (ScanResult, error) {
	var threats []Threat
	var flags []string

	for _, p := range ps.patterns {
		loc := p.regex.FindIndex(content)
		if loc != nil {
			threats = append(threats, Threat{
				Category: p.category,
				Severity: p.severity,
				Pattern:  p.name,
				Location: string(content[loc[0]:loc[1]]),
			})
			flags = append(flags, p.category+"_"+p.name)
		}
	}

	if len(threats) == 0 {
		return ScanResult{
			Decision: "allow",
			Reason:   "no threats detected",
		}, nil
	}

	// Determine highest severity
	decision := "flag"
	for _, t := range threats {
		if t.Severity == "critical" || t.Severity == "high" {
			decision = "block"
			break
		}
	}

	var b strings.Builder
	b.WriteString("detected threats:")
	for i, t := range threats {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(" ")
		b.WriteString(t.Pattern)
		b.WriteString(" (")
		b.WriteString(t.Severity)
		b.WriteByte(')')
	}
	reason := b.String()

	return ScanResult{
		Decision: decision,
		Flags:    flags,
		Reason:   reason,
		Threats:  threats,
	}, nil
}
