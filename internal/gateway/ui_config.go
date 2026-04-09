// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// MCP-UI Gateway Configuration - RFA-j2d.9
// Defines the configuration schema for MCP-UI (Apps Extension) security controls
// as specified in Reference Architecture Section 7.9.10.
//
// Configuration hierarchy principle:
// Hard constraints (set by security team, checked into policy) CANNOT be overridden
// by capability grants. Capability grants can only ENABLE capabilities within the
// boundaries of hard constraints.
//
// Example: A permissive grant cannot enable camera access when
// permissions_hard_constraints.camera_allowed=false.
package gateway

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// UIConfig holds the full MCP-UI configuration for the gateway.
// Maps to the ui: section in gateway YAML config.
type UIConfig struct {
	// Global kill switch: if false, all UI is stripped regardless of grants
	Enabled bool `yaml:"enabled"`

	// Default mode for servers without explicit grants: deny | audit-only | allow
	DefaultMode string `yaml:"default_mode"`

	// Global resource limits
	MaxResourceSizeBytes        int64 `yaml:"max_resource_size_bytes"`
	ResourceFetchTimeoutSeconds int   `yaml:"resource_fetch_timeout_seconds"`
	ResourceCacheTTLSeconds     int   `yaml:"resource_cache_ttl_seconds"`

	// Content scanning
	ScanEnabled              bool `yaml:"scan_enabled"`
	BlockOnDangerousPatterns bool `yaml:"block_on_dangerous_patterns"`

	// Hash verification (extends tool registry pattern)
	HashVerificationEnabled bool `yaml:"hash_verification_enabled"`

	// CSP hard constraints (cannot be overridden by grants)
	CSPHardConstraints CSPHardConstraints `yaml:"csp_hard_constraints"`

	// Permissions hard constraints
	PermissionsHardConstraints PermissionsHardConstraints `yaml:"permissions_hard_constraints"`

	// App-driven tool call controls
	AppToolCalls AppToolCallConfig `yaml:"app_tool_calls"`

	// Host compatibility: downgrade for older clients
	StripUIForIncompatibleHosts bool `yaml:"strip_ui_for_incompatible_hosts"`
}

// CSPHardConstraints defines Content Security Policy limits that cannot be
// overridden by capability grants. These are security boundaries enforced
// by the gateway regardless of what the MCP server requests.
type CSPHardConstraints struct {
	FrameDomainsAllowed   bool `yaml:"frame_domains_allowed"`    // Nested iframes always denied if false
	BaseURIDomainsAllowed bool `yaml:"base_uri_domains_allowed"` // Always same-origin if false
	MaxConnectDomains     int  `yaml:"max_connect_domains"`      // Maximum external origins per app
	MaxResourceDomains    int  `yaml:"max_resource_domains"`     // Maximum static resource origins
}

// PermissionsHardConstraints defines browser permission policies that cannot
// be overridden by capability grants. These represent security decisions
// made by the security team and checked into policy.
type PermissionsHardConstraints struct {
	CameraAllowed         bool `yaml:"camera_allowed"`
	MicrophoneAllowed     bool `yaml:"microphone_allowed"`
	GeolocationAllowed    bool `yaml:"geolocation_allowed"`
	ClipboardWriteAllowed bool `yaml:"clipboard_write_allowed"`
}

// AppToolCallConfig controls how MCP-UI apps can invoke tool calls
// through the gateway, with separate rate limiting and risk gating.
type AppToolCallConfig struct {
	SeparateRateLimit      bool `yaml:"separate_rate_limit"`
	RequestsPerMinute      int  `yaml:"requests_per_minute"`
	Burst                  int  `yaml:"burst"`
	ForceStepUpForHighRisk bool `yaml:"force_step_up_for_high_risk"`
}

// CapabilityGrant represents what a capability grant requests.
// Hard constraints are checked against these requests -- if a grant
// requests something denied by a hard constraint, the request is rejected.
type CapabilityGrant struct {
	CameraRequested         bool
	MicrophoneRequested     bool
	GeolocationRequested    bool
	ClipboardWriteRequested bool
	ConnectDomains          int  // Number of connect-src domains requested
	ResourceDomains         int  // Number of resource domains requested
	FrameDomainsRequested   bool // Whether frame embedding is requested
	BaseURIDomainsRequested bool // Whether non-same-origin base-uri is requested
}

// validDefaultModes lists the accepted values for DefaultMode.
var validDefaultModes = map[string]bool{
	"deny":       true,
	"audit-only": true,
	"allow":      true,
}

// UIConfigDefaults returns a UIConfig with all fields set to their
// secure-by-default values as defined in Section 7.9.10.
func UIConfigDefaults() *UIConfig {
	return &UIConfig{
		Enabled:                     false,
		DefaultMode:                 "deny",
		MaxResourceSizeBytes:        2097152, // 2 MB
		ResourceFetchTimeoutSeconds: 10,
		ResourceCacheTTLSeconds:     300,
		ScanEnabled:                 true,
		BlockOnDangerousPatterns:    true,
		HashVerificationEnabled:     true,
		CSPHardConstraints: CSPHardConstraints{
			FrameDomainsAllowed:   false,
			BaseURIDomainsAllowed: false,
			MaxConnectDomains:     5,
			MaxResourceDomains:    10,
		},
		PermissionsHardConstraints: PermissionsHardConstraints{
			CameraAllowed:         false,
			MicrophoneAllowed:     false,
			GeolocationAllowed:    false,
			ClipboardWriteAllowed: false,
		},
		AppToolCalls: AppToolCallConfig{
			SeparateRateLimit:      true,
			RequestsPerMinute:      20,
			Burst:                  5,
			ForceStepUpForHighRisk: true,
		},
		StripUIForIncompatibleHosts: true,
	}
}

// Validate checks the UIConfig for invalid values. Returns a list of
// warnings (non-fatal) and an error if any field is invalid.
// All validation errors are collected and returned together.
func (c *UIConfig) Validate() (warnings []string, err error) {
	var errs []string

	// default_mode must be one of the valid values
	if !validDefaultModes[c.DefaultMode] {
		errs = append(errs, fmt.Sprintf("default_mode must be one of deny, audit-only, allow; got %q", c.DefaultMode))
	}

	// max_resource_size_bytes must be positive
	if c.MaxResourceSizeBytes <= 0 {
		errs = append(errs, fmt.Sprintf("max_resource_size_bytes must be positive; got %d", c.MaxResourceSizeBytes))
	}

	// resource_fetch_timeout_seconds must be positive
	if c.ResourceFetchTimeoutSeconds <= 0 {
		errs = append(errs, fmt.Sprintf("resource_fetch_timeout_seconds must be positive; got %d", c.ResourceFetchTimeoutSeconds))
	}

	// Warn if enabled=true but default_mode=allow (too permissive)
	if c.Enabled && c.DefaultMode == "allow" {
		warnings = append(warnings, "ui.enabled=true with default_mode=allow is too permissive; consider using deny or audit-only")
	}

	if len(errs) > 0 {
		return warnings, fmt.Errorf("ui config validation failed: %s", strings.Join(errs, "; "))
	}

	return warnings, nil
}

// ApplyEnvOverrides reads environment variables and overrides the
// corresponding UIConfig fields. Empty env vars are ignored.
// Invalid values (e.g., non-numeric for int fields) are silently ignored
// to match the pattern used by ConfigFromEnv().
func (c *UIConfig) ApplyEnvOverrides() {
	if v := os.Getenv("UI_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			c.Enabled = parsed
		}
	}

	if v := os.Getenv("UI_DEFAULT_MODE"); v != "" {
		c.DefaultMode = v
	}

	if v := os.Getenv("UI_MAX_RESOURCE_SIZE_BYTES"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			c.MaxResourceSizeBytes = parsed
		}
	}

	if v := os.Getenv("UI_RESOURCE_FETCH_TIMEOUT_SECONDS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			c.ResourceFetchTimeoutSeconds = parsed
		}
	}

	if v := os.Getenv("UI_SCAN_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			c.ScanEnabled = parsed
		}
	}

	if v := os.Getenv("UI_HASH_VERIFICATION_ENABLED"); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			c.HashVerificationEnabled = parsed
		}
	}
}

// EnforceHardConstraints checks a capability grant against the hard
// constraints in the UIConfig. Returns a list of violations (empty if
// the grant is within bounds). This implements the configuration
// hierarchy principle: hard constraints CANNOT be overridden by grants.
func (c *UIConfig) EnforceHardConstraints(grant CapabilityGrant) []string {
	var violations []string

	// Permission constraints
	if grant.CameraRequested && !c.PermissionsHardConstraints.CameraAllowed {
		violations = append(violations, "camera access denied by hard constraint (permissions_hard_constraints.camera_allowed=false)")
	}
	if grant.MicrophoneRequested && !c.PermissionsHardConstraints.MicrophoneAllowed {
		violations = append(violations, "microphone access denied by hard constraint (permissions_hard_constraints.microphone_allowed=false)")
	}
	if grant.GeolocationRequested && !c.PermissionsHardConstraints.GeolocationAllowed {
		violations = append(violations, "geolocation access denied by hard constraint (permissions_hard_constraints.geolocation_allowed=false)")
	}
	if grant.ClipboardWriteRequested && !c.PermissionsHardConstraints.ClipboardWriteAllowed {
		violations = append(violations, "clipboard write access denied by hard constraint (permissions_hard_constraints.clipboard_write_allowed=false)")
	}

	// CSP constraints
	if grant.FrameDomainsRequested && !c.CSPHardConstraints.FrameDomainsAllowed {
		violations = append(violations, "frame embedding denied by hard constraint (csp_hard_constraints.frame_domains_allowed=false)")
	}
	if grant.BaseURIDomainsRequested && !c.CSPHardConstraints.BaseURIDomainsAllowed {
		violations = append(violations, "non-same-origin base-uri denied by hard constraint (csp_hard_constraints.base_uri_domains_allowed=false)")
	}
	if grant.ConnectDomains > c.CSPHardConstraints.MaxConnectDomains {
		violations = append(violations, fmt.Sprintf(
			"connect domains (%d) exceeds hard constraint max_connect_domains (%d)",
			grant.ConnectDomains, c.CSPHardConstraints.MaxConnectDomains,
		))
	}
	if grant.ResourceDomains > c.CSPHardConstraints.MaxResourceDomains {
		violations = append(violations, fmt.Sprintf(
			"resource domains (%d) exceeds hard constraint max_resource_domains (%d)",
			grant.ResourceDomains, c.CSPHardConstraints.MaxResourceDomains,
		))
	}

	return violations
}

// uiConfigFileWrapper is the top-level YAML structure for UI config files.
// It wraps UIConfig under the "ui:" key to match the expected YAML format.
type uiConfigFileWrapper struct {
	UI UIConfig `yaml:"ui"`
}

// LoadUIConfig loads a UIConfig from a YAML file. The file must have a
// top-level "ui:" key. Fields not specified in the file receive their
// default values from UIConfigDefaults().
func LoadUIConfig(path string) (*UIConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read UI config file %s: %w", path, err)
	}

	// Start with defaults so unspecified fields get proper values
	defaults := UIConfigDefaults()
	wrapper := uiConfigFileWrapper{
		UI: *defaults,
	}

	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse UI config YAML: %w", err)
	}

	return &wrapper.UI, nil
}
