package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Default Values Tests ---

func TestUIConfigDefaultValues(t *testing.T) {
	cfg := UIConfigDefaults()

	// AC#2: Default values set per story spec
	if cfg.Enabled {
		t.Error("Expected Enabled=false by default")
	}
	if cfg.DefaultMode != "deny" {
		t.Errorf("Expected DefaultMode=deny, got %s", cfg.DefaultMode)
	}
	if cfg.MaxResourceSizeBytes != 2097152 {
		t.Errorf("Expected MaxResourceSizeBytes=2097152 (2MB), got %d", cfg.MaxResourceSizeBytes)
	}
	if cfg.ResourceFetchTimeoutSeconds != 10 {
		t.Errorf("Expected ResourceFetchTimeoutSeconds=10, got %d", cfg.ResourceFetchTimeoutSeconds)
	}
	if cfg.ResourceCacheTTLSeconds != 300 {
		t.Errorf("Expected ResourceCacheTTLSeconds=300, got %d", cfg.ResourceCacheTTLSeconds)
	}
	if !cfg.ScanEnabled {
		t.Error("Expected ScanEnabled=true by default")
	}
	if !cfg.BlockOnDangerousPatterns {
		t.Error("Expected BlockOnDangerousPatterns=true by default")
	}
	if !cfg.HashVerificationEnabled {
		t.Error("Expected HashVerificationEnabled=true by default")
	}
	if !cfg.StripUIForIncompatibleHosts {
		t.Error("Expected StripUIForIncompatibleHosts=true by default")
	}
}

func TestUIConfigDefaultCSPHardConstraints(t *testing.T) {
	cfg := UIConfigDefaults()
	csp := cfg.CSPHardConstraints

	if csp.FrameDomainsAllowed {
		t.Error("Expected FrameDomainsAllowed=false (nested iframes always denied)")
	}
	if csp.BaseURIDomainsAllowed {
		t.Error("Expected BaseURIDomainsAllowed=false (always same-origin)")
	}
	if csp.MaxConnectDomains != 5 {
		t.Errorf("Expected MaxConnectDomains=5, got %d", csp.MaxConnectDomains)
	}
	if csp.MaxResourceDomains != 10 {
		t.Errorf("Expected MaxResourceDomains=10, got %d", csp.MaxResourceDomains)
	}
}

func TestUIConfigDefaultPermissionsHardConstraints(t *testing.T) {
	cfg := UIConfigDefaults()
	perm := cfg.PermissionsHardConstraints

	if perm.CameraAllowed {
		t.Error("Expected CameraAllowed=false by default")
	}
	if perm.MicrophoneAllowed {
		t.Error("Expected MicrophoneAllowed=false by default")
	}
	if perm.GeolocationAllowed {
		t.Error("Expected GeolocationAllowed=false by default")
	}
	if perm.ClipboardWriteAllowed {
		t.Error("Expected ClipboardWriteAllowed=false by default")
	}
}

func TestUIConfigDefaultAppToolCalls(t *testing.T) {
	cfg := UIConfigDefaults()
	app := cfg.AppToolCalls

	if !app.SeparateRateLimit {
		t.Error("Expected SeparateRateLimit=true by default")
	}
	if app.RequestsPerMinute != 20 {
		t.Errorf("Expected RequestsPerMinute=20, got %d", app.RequestsPerMinute)
	}
	if app.Burst != 5 {
		t.Errorf("Expected Burst=5, got %d", app.Burst)
	}
	if !app.ForceStepUpForHighRisk {
		t.Error("Expected ForceStepUpForHighRisk=true by default")
	}
}

// --- YAML Parsing Tests ---

func TestLoadUIConfigFromYAML(t *testing.T) {
	yamlContent := `
ui:
  enabled: true
  default_mode: "audit-only"
  max_resource_size_bytes: 4194304
  resource_fetch_timeout_seconds: 30
  resource_cache_ttl_seconds: 600
  scan_enabled: false
  block_on_dangerous_patterns: false
  hash_verification_enabled: false
  csp_hard_constraints:
    frame_domains_allowed: false
    base_uri_domains_allowed: false
    max_connect_domains: 3
    max_resource_domains: 7
  permissions_hard_constraints:
    camera_allowed: false
    microphone_allowed: false
    geolocation_allowed: false
    clipboard_write_allowed: false
  app_tool_calls:
    separate_rate_limit: false
    requests_per_minute: 50
    burst: 10
    force_step_up_for_high_risk: false
  strip_ui_for_incompatible_hosts: false
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ui_config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	cfg, err := LoadUIConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load UI config: %v", err)
	}

	// Verify all fields parsed correctly
	if !cfg.Enabled {
		t.Error("Expected Enabled=true")
	}
	if cfg.DefaultMode != "audit-only" {
		t.Errorf("Expected DefaultMode=audit-only, got %s", cfg.DefaultMode)
	}
	if cfg.MaxResourceSizeBytes != 4194304 {
		t.Errorf("Expected MaxResourceSizeBytes=4194304, got %d", cfg.MaxResourceSizeBytes)
	}
	if cfg.ResourceFetchTimeoutSeconds != 30 {
		t.Errorf("Expected ResourceFetchTimeoutSeconds=30, got %d", cfg.ResourceFetchTimeoutSeconds)
	}
	if cfg.ResourceCacheTTLSeconds != 600 {
		t.Errorf("Expected ResourceCacheTTLSeconds=600, got %d", cfg.ResourceCacheTTLSeconds)
	}
	if cfg.ScanEnabled {
		t.Error("Expected ScanEnabled=false")
	}
	if cfg.BlockOnDangerousPatterns {
		t.Error("Expected BlockOnDangerousPatterns=false")
	}
	if cfg.HashVerificationEnabled {
		t.Error("Expected HashVerificationEnabled=false")
	}
	if cfg.StripUIForIncompatibleHosts {
		t.Error("Expected StripUIForIncompatibleHosts=false (YAML explicitly sets it)")
	}

	// CSP constraints
	if cfg.CSPHardConstraints.MaxConnectDomains != 3 {
		t.Errorf("Expected MaxConnectDomains=3, got %d", cfg.CSPHardConstraints.MaxConnectDomains)
	}
	if cfg.CSPHardConstraints.MaxResourceDomains != 7 {
		t.Errorf("Expected MaxResourceDomains=7, got %d", cfg.CSPHardConstraints.MaxResourceDomains)
	}

	// App tool calls
	if cfg.AppToolCalls.SeparateRateLimit {
		t.Error("Expected SeparateRateLimit=false")
	}
	if cfg.AppToolCalls.RequestsPerMinute != 50 {
		t.Errorf("Expected RequestsPerMinute=50, got %d", cfg.AppToolCalls.RequestsPerMinute)
	}
	if cfg.AppToolCalls.Burst != 10 {
		t.Errorf("Expected Burst=10, got %d", cfg.AppToolCalls.Burst)
	}
}

func TestLoadUIConfigFromYAML_StripUIFalseExplicit(t *testing.T) {
	yamlContent := `
ui:
  strip_ui_for_incompatible_hosts: false
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "ui_config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	cfg, err := LoadUIConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load UI config: %v", err)
	}

	if cfg.StripUIForIncompatibleHosts {
		t.Error("Expected StripUIForIncompatibleHosts=false when explicitly set in YAML")
	}
}

func TestLoadUIConfigFileNotFound(t *testing.T) {
	_, err := LoadUIConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadUIConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(tmpFile, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	_, err := LoadUIConfig(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadUIConfigPartialYAML_DefaultsFillIn(t *testing.T) {
	// Only specify some fields; others should get defaults
	yamlContent := `
ui:
  enabled: true
  default_mode: "allow"
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "partial.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	cfg, err := LoadUIConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load UI config: %v", err)
	}

	if !cfg.Enabled {
		t.Error("Expected Enabled=true from YAML")
	}
	if cfg.DefaultMode != "allow" {
		t.Errorf("Expected DefaultMode=allow, got %s", cfg.DefaultMode)
	}
	// Defaults should fill in for unspecified fields
	if cfg.MaxResourceSizeBytes != 2097152 {
		t.Errorf("Expected default MaxResourceSizeBytes=2097152, got %d", cfg.MaxResourceSizeBytes)
	}
	if cfg.ResourceFetchTimeoutSeconds != 10 {
		t.Errorf("Expected default ResourceFetchTimeoutSeconds=10, got %d", cfg.ResourceFetchTimeoutSeconds)
	}
	if cfg.CSPHardConstraints.MaxConnectDomains != 5 {
		t.Errorf("Expected default MaxConnectDomains=5, got %d", cfg.CSPHardConstraints.MaxConnectDomains)
	}
}

// --- Validation Tests ---

func TestUIConfigValidate_ValidConfigs(t *testing.T) {
	testCases := []struct {
		name string
		mode string
	}{
		{"deny mode", "deny"},
		{"audit-only mode", "audit-only"},
		{"allow mode", "allow"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := UIConfigDefaults()
			cfg.DefaultMode = tc.mode
			warnings, err := cfg.Validate()
			if err != nil {
				t.Errorf("Expected no error for valid config (%s), got: %v", tc.mode, err)
			}
			// Only warns when enabled=true AND mode=allow.
			if tc.mode == "allow" && cfg.Enabled && len(warnings) == 0 {
				t.Error("Expected warning when enabled=true and default_mode=allow")
			}
		})
	}
}

func TestUIConfigValidate_InvalidDefaultMode(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.DefaultMode = "invalid-mode"

	_, err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for invalid default_mode")
	}
	if !strings.Contains(err.Error(), "default_mode") {
		t.Errorf("Error should mention default_mode, got: %v", err)
	}
}

func TestUIConfigValidate_EmptyDefaultMode(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.DefaultMode = ""

	_, err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for empty default_mode")
	}
}

func TestUIConfigValidate_NonPositiveMaxResourceSize(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.MaxResourceSizeBytes = 0

	_, err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for zero MaxResourceSizeBytes")
	}

	cfg.MaxResourceSizeBytes = -1
	_, err = cfg.Validate()
	if err == nil {
		t.Error("Expected error for negative MaxResourceSizeBytes")
	}
}

func TestUIConfigValidate_NonPositiveFetchTimeout(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.ResourceFetchTimeoutSeconds = 0

	_, err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for zero ResourceFetchTimeoutSeconds")
	}

	cfg.ResourceFetchTimeoutSeconds = -5
	_, err = cfg.Validate()
	if err == nil {
		t.Error("Expected error for negative ResourceFetchTimeoutSeconds")
	}
}

func TestUIConfigValidate_WarningEnabledWithAllow(t *testing.T) {
	// AC#6: Warning emitted if enabled=true with default_mode=allow
	cfg := UIConfigDefaults()
	cfg.Enabled = true
	cfg.DefaultMode = "allow"

	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Expected no error (warning only), got: %v", err)
	}
	if len(warnings) == 0 {
		t.Error("Expected at least one warning for enabled=true with default_mode=allow")
	}

	foundPermissiveWarning := false
	for _, w := range warnings {
		if strings.Contains(w, "allow") && strings.Contains(w, "permissive") {
			foundPermissiveWarning = true
		}
	}
	if !foundPermissiveWarning {
		t.Errorf("Expected warning about permissive config, got warnings: %v", warnings)
	}
}

func TestUIConfigValidate_NoWarningWhenDisabledWithAllow(t *testing.T) {
	// enabled=false + default_mode=allow should NOT warn (UI is disabled anyway)
	cfg := UIConfigDefaults()
	cfg.Enabled = false
	cfg.DefaultMode = "allow"

	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings when UI is disabled, got: %v", warnings)
	}
}

func TestUIConfigValidate_NoWarningForDenyMode(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.Enabled = true
	cfg.DefaultMode = "deny"

	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for deny mode, got: %v", warnings)
	}
}

// --- Environment Variable Override Tests ---

func TestUIConfigApplyEnvOverrides_UIEnabled(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_ENABLED", "true")
	cfg.ApplyEnvOverrides()

	if !cfg.Enabled {
		t.Error("Expected UI_ENABLED=true to set Enabled=true")
	}

	t.Setenv("UI_ENABLED", "false")
	cfg.ApplyEnvOverrides()

	if cfg.Enabled {
		t.Error("Expected UI_ENABLED=false to set Enabled=false")
	}
}

func TestUIConfigApplyEnvOverrides_DefaultMode(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_DEFAULT_MODE", "audit-only")
	cfg.ApplyEnvOverrides()

	if cfg.DefaultMode != "audit-only" {
		t.Errorf("Expected DefaultMode=audit-only, got %s", cfg.DefaultMode)
	}
}

func TestUIConfigApplyEnvOverrides_MaxResourceSizeBytes(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_MAX_RESOURCE_SIZE_BYTES", "5242880")
	cfg.ApplyEnvOverrides()

	if cfg.MaxResourceSizeBytes != 5242880 {
		t.Errorf("Expected MaxResourceSizeBytes=5242880, got %d", cfg.MaxResourceSizeBytes)
	}
}

func TestUIConfigApplyEnvOverrides_ResourceFetchTimeout(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_RESOURCE_FETCH_TIMEOUT_SECONDS", "30")
	cfg.ApplyEnvOverrides()

	if cfg.ResourceFetchTimeoutSeconds != 30 {
		t.Errorf("Expected ResourceFetchTimeoutSeconds=30, got %d", cfg.ResourceFetchTimeoutSeconds)
	}
}

func TestUIConfigApplyEnvOverrides_ScanEnabled(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_SCAN_ENABLED", "false")
	cfg.ApplyEnvOverrides()

	if cfg.ScanEnabled {
		t.Error("Expected ScanEnabled=false after env override")
	}
}

func TestUIConfigApplyEnvOverrides_HashVerification(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_HASH_VERIFICATION_ENABLED", "false")
	cfg.ApplyEnvOverrides()

	if cfg.HashVerificationEnabled {
		t.Error("Expected HashVerificationEnabled=false after env override")
	}
}

func TestUIConfigApplyEnvOverrides_InvalidIntIgnored(t *testing.T) {
	cfg := UIConfigDefaults()
	original := cfg.MaxResourceSizeBytes

	t.Setenv("UI_MAX_RESOURCE_SIZE_BYTES", "not-a-number")
	cfg.ApplyEnvOverrides()

	if cfg.MaxResourceSizeBytes != original {
		t.Errorf("Expected MaxResourceSizeBytes unchanged for invalid int, got %d", cfg.MaxResourceSizeBytes)
	}
}

func TestUIConfigApplyEnvOverrides_InvalidBoolIgnored(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_ENABLED", "not-a-bool")
	cfg.ApplyEnvOverrides()

	// Should remain at default (false)
	if cfg.Enabled {
		t.Error("Expected Enabled unchanged for invalid bool")
	}
}

func TestUIConfigApplyEnvOverrides_EmptyValueIgnored(t *testing.T) {
	cfg := UIConfigDefaults()

	t.Setenv("UI_ENABLED", "")
	t.Setenv("UI_DEFAULT_MODE", "")
	cfg.ApplyEnvOverrides()

	// Should remain at defaults
	if cfg.Enabled {
		t.Error("Expected Enabled unchanged for empty env var")
	}
	if cfg.DefaultMode != "deny" {
		t.Errorf("Expected DefaultMode=deny for empty env var, got %s", cfg.DefaultMode)
	}
}

// --- Hard Constraint Enforcement Tests ---

func TestEnforceHardConstraints_CameraDenied(t *testing.T) {
	cfg := UIConfigDefaults()
	// Default: camera_allowed=false

	grant := CapabilityGrant{
		CameraRequested:         true,
		MicrophoneRequested:     false,
		GeolocationRequested:    false,
		ClipboardWriteRequested: false,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) == 0 {
		t.Error("Expected violation when requesting camera with camera_allowed=false")
	}
	foundCamera := false
	for _, v := range violations {
		if strings.Contains(v, "camera") {
			foundCamera = true
		}
	}
	if !foundCamera {
		t.Errorf("Expected camera violation, got: %v", violations)
	}
}

func TestEnforceHardConstraints_AllPermissionsDenied(t *testing.T) {
	cfg := UIConfigDefaults()
	// All permissions false by default

	grant := CapabilityGrant{
		CameraRequested:         true,
		MicrophoneRequested:     true,
		GeolocationRequested:    true,
		ClipboardWriteRequested: true,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) != 4 {
		t.Errorf("Expected 4 violations for all denied permissions, got %d: %v", len(violations), violations)
	}
}

func TestEnforceHardConstraints_NoViolationsWhenNotRequested(t *testing.T) {
	cfg := UIConfigDefaults()

	// Grant requests nothing that is denied
	grant := CapabilityGrant{
		CameraRequested:         false,
		MicrophoneRequested:     false,
		GeolocationRequested:    false,
		ClipboardWriteRequested: false,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) != 0 {
		t.Errorf("Expected no violations when nothing restricted is requested, got: %v", violations)
	}
}

func TestEnforceHardConstraints_AllowedWhenConstraintPermits(t *testing.T) {
	cfg := UIConfigDefaults()
	// Override: allow camera
	cfg.PermissionsHardConstraints.CameraAllowed = true

	grant := CapabilityGrant{
		CameraRequested: true,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) != 0 {
		t.Errorf("Expected no violations when camera is allowed by hard constraint, got: %v", violations)
	}
}

func TestEnforceHardConstraints_CSPConnectDomainLimit(t *testing.T) {
	cfg := UIConfigDefaults()
	// Default max_connect_domains=5

	grant := CapabilityGrant{
		ConnectDomains: 6, // exceeds limit
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) == 0 {
		t.Error("Expected violation when connect_domains exceeds max_connect_domains")
	}
}

func TestEnforceHardConstraints_CSPConnectDomainAtLimit(t *testing.T) {
	cfg := UIConfigDefaults()

	grant := CapabilityGrant{
		ConnectDomains: 5, // exactly at limit
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) != 0 {
		t.Errorf("Expected no violation when at exactly the limit, got: %v", violations)
	}
}

func TestEnforceHardConstraints_CSPResourceDomainLimit(t *testing.T) {
	cfg := UIConfigDefaults()
	// Default max_resource_domains=10

	grant := CapabilityGrant{
		ResourceDomains: 11, // exceeds limit
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) == 0 {
		t.Error("Expected violation when resource_domains exceeds max_resource_domains")
	}
}

func TestEnforceHardConstraints_FrameDomainsAlwaysDenied(t *testing.T) {
	cfg := UIConfigDefaults()
	// frame_domains_allowed=false by default

	grant := CapabilityGrant{
		FrameDomainsRequested: true,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) == 0 {
		t.Error("Expected violation when requesting frame_domains with frame_domains_allowed=false")
	}
}

func TestEnforceHardConstraints_BaseURIAlwaysDenied(t *testing.T) {
	cfg := UIConfigDefaults()

	grant := CapabilityGrant{
		BaseURIDomainsRequested: true,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) == 0 {
		t.Error("Expected violation when requesting base_uri_domains with base_uri_domains_allowed=false")
	}
}

func TestEnforceHardConstraints_MultipleViolations(t *testing.T) {
	cfg := UIConfigDefaults()

	grant := CapabilityGrant{
		CameraRequested:         true,
		FrameDomainsRequested:   true,
		ConnectDomains:          100,
		ResourceDomains:         100,
		BaseURIDomainsRequested: true,
	}

	violations := cfg.EnforceHardConstraints(grant)
	if len(violations) < 4 {
		t.Errorf("Expected at least 4 violations for multiple constraint violations, got %d: %v", len(violations), violations)
	}
}

// --- Integration: Config struct includes UIConfig ---

func TestConfigStructHasUIConfig(t *testing.T) {
	cfg := ConfigFromEnv()
	// UIConfig should be initialized with defaults when no YAML is provided
	if cfg.UI.DefaultMode != "deny" {
		t.Errorf("Expected Config.UI.DefaultMode=deny by default, got %s", cfg.UI.DefaultMode)
	}
	if cfg.UI.Enabled {
		t.Error("Expected Config.UI.Enabled=false by default")
	}
}

// --- Full round-trip: YAML + env override + validation ---

func TestUIConfigFullRoundTrip(t *testing.T) {
	// 1. Load from YAML
	yamlContent := `
ui:
  enabled: false
  default_mode: "deny"
  max_resource_size_bytes: 1048576
  resource_fetch_timeout_seconds: 5
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	cfg, err := LoadUIConfig(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load UI config: %v", err)
	}

	// 2. Apply env override to enable UI
	t.Setenv("UI_ENABLED", "true")
	t.Setenv("UI_DEFAULT_MODE", "audit-only")
	cfg.ApplyEnvOverrides()

	if !cfg.Enabled {
		t.Error("Expected Enabled=true after env override")
	}
	if cfg.DefaultMode != "audit-only" {
		t.Errorf("Expected DefaultMode=audit-only after env override, got %s", cfg.DefaultMode)
	}

	// 3. Validate (audit-only with enabled=true should be fine, no warnings)
	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for audit-only mode, got: %v", warnings)
	}

	// 4. Values from YAML preserved where env didn't override
	if cfg.MaxResourceSizeBytes != 1048576 {
		t.Errorf("Expected MaxResourceSizeBytes=1048576 from YAML, got %d", cfg.MaxResourceSizeBytes)
	}
	if cfg.ResourceFetchTimeoutSeconds != 5 {
		t.Errorf("Expected ResourceFetchTimeoutSeconds=5 from YAML, got %d", cfg.ResourceFetchTimeoutSeconds)
	}
}

// --- Edge Cases ---

func TestUIConfigValidate_MultipleErrors(t *testing.T) {
	cfg := UIConfigDefaults()
	cfg.DefaultMode = "bogus"
	cfg.MaxResourceSizeBytes = -1
	cfg.ResourceFetchTimeoutSeconds = 0

	_, err := cfg.Validate()
	if err == nil {
		t.Error("Expected error for multiple invalid fields")
	}
	// Should report all errors, not just the first one
	errStr := err.Error()
	if !strings.Contains(errStr, "default_mode") {
		t.Errorf("Expected error to mention default_mode, got: %s", errStr)
	}
	if !strings.Contains(errStr, "max_resource_size_bytes") {
		t.Errorf("Expected error to mention max_resource_size_bytes, got: %s", errStr)
	}
	if !strings.Contains(errStr, "resource_fetch_timeout_seconds") {
		t.Errorf("Expected error to mention resource_fetch_timeout_seconds, got: %s", errStr)
	}
}

func TestUIConfigValidate_ZeroCacheTTLAllowed(t *testing.T) {
	// Cache TTL of 0 means "no caching" - this is a valid choice
	cfg := UIConfigDefaults()
	cfg.ResourceCacheTTLSeconds = 0

	warnings, err := cfg.Validate()
	if err != nil {
		t.Errorf("Expected no error for zero cache TTL, got: %v", err)
	}
	_ = warnings
}
