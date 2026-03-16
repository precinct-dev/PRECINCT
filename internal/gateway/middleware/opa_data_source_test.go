package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

// dataSourcePolicy is the Rego policy for data source access control.
// Embedded here to avoid coupling test execution to config file paths.
const dataSourcePolicy = `package precinct.data_source

import rego.v1

default allow := false

allow if {
    input.data_source.registered == true
    data_source_grant[_]
}

allow if {
    input.data_source.registered == false
    input.session.risk_score <= 5
}

data_source_grant[grant] if {
    some grant in data.data_source_grants
    glob.match(grant.spiffe_pattern, ["/"], input.spiffe_id)
    glob.match(grant.uri_pattern, [], input.data_source.uri)
}

deny contains "mutable_source_requires_admin" if {
    input.data_source.registered == true
    input.data_source.mutable_policy != "block_on_change"
    not admin_identity
}

admin_identity if {
    startswith(input.spiffe_id, "spiffe://poc.local/admin/")
}

deny contains "unregistered_high_risk" if {
    input.data_source.registered == false
    input.session.risk_score > 5
}
`

// dataSourceGrants is the YAML data file that feeds data.data_source_grants.
// URI patterns use "**" for catch-all matching because OPA glob treats "."
// as a default separator, so plain "*" would not cross domain segments.
const dataSourceGrants = `data_source_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    uri_pattern: "https://gist.github.com/**"
    description: "Research agents - GitHub gist access"
  - spiffe_pattern: "spiffe://poc.local/admin/*"
    uri_pattern: "**"
    description: "Admin identities - full data source access"
  - spiffe_pattern: "spiffe://poc.local/gateways/precinct-gateway/dev"
    uri_pattern: "**"
    description: "Gateway - full data source access"
`

// mcpPolicyStub is a minimal MCP policy so the main OPA query compiles.
const mcpPolicyStub = `package mcp
default allow := {"allow": true, "reason": "allowed"}
`

// setupDataSourcePolicyDir creates a temp directory with the data source policy,
// grants data, and a stub MCP policy. Returns the directory path.
func setupDataSourcePolicyDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	files := map[string]string{
		"data_source_policy.rego": dataSourcePolicy,
		"data_source_grants.yaml": dataSourceGrants,
		"mcp_policy.rego":         mcpPolicyStub,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", name, err)
		}
	}
	return tmpDir
}

// TestDataSourceInput_JSONTags verifies the struct tags are present and correct
// by marshaling a DataSourceInput to JSON.
func TestDataSourceInput_JSONTags(t *testing.T) {
	ds := DataSourceInput{
		URI:            "https://example.com/data",
		Registered:     true,
		MutablePolicy:  "block_on_change",
		ContentChanged: false,
	}
	if ds.URI != "https://example.com/data" {
		t.Errorf("Expected URI field, got %s", ds.URI)
	}
	if !ds.Registered {
		t.Error("Expected Registered=true")
	}
	if ds.MutablePolicy != "block_on_change" {
		t.Errorf("Expected MutablePolicy=block_on_change, got %s", ds.MutablePolicy)
	}
	if ds.ContentChanged {
		t.Error("Expected ContentChanged=false")
	}
}

// TestOPAInput_DataSourceField verifies that OPAInput accepts DataSource field.
func TestOPAInput_DataSourceField(t *testing.T) {
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/abc123",
			Registered:     true,
			MutablePolicy:  "block_on_change",
			ContentChanged: false,
		},
	}
	if input.DataSource == nil {
		t.Fatal("DataSource field should not be nil")
	}
	if input.DataSource.URI != "https://gist.github.com/abc123" {
		t.Errorf("Expected URI, got %s", input.DataSource.URI)
	}
}

// TestOPAInput_DataSourceOmitempty verifies DataSource is omitted when nil.
func TestOPAInput_DataSourceOmitempty(t *testing.T) {
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/test",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
	}
	if input.DataSource != nil {
		t.Error("DataSource should be nil by default")
	}
}

// TestEvaluateDataSourcePolicy_RegisteredSourceWithGrant verifies that a registered
// data source with a matching SPIFFE ID grant is allowed.
func TestEvaluateDataSourcePolicy_RegisteredSourceWithGrant(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/abc123",
			Registered:     true,
			MutablePolicy:  "block_on_change",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("Expected allowed=true for registered source with grant, got denied: %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_RegisteredSourceWithoutGrant verifies that a registered
// data source WITHOUT a matching SPIFFE ID grant is denied.
func TestEvaluateDataSourcePolicy_RegisteredSourceWithoutGrant(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/unauthorized-agent/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/secret-data",
			Registered:     true,
			MutablePolicy:  "block_on_change",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if result.Allowed {
		t.Error("Expected denied for registered source without grant, got allowed")
	}
	if len(result.DenyReasons) == 0 {
		t.Error("Expected at least one deny reason")
	}
}

// TestEvaluateDataSourcePolicy_MutableSourceNonAdmin verifies that a mutable data
// source (mutable_policy != "block_on_change") is denied for non-admin identities.
func TestEvaluateDataSourcePolicy_MutableSourceNonAdmin(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Researcher has a grant for gist.github.com but is not admin
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/mutable-data",
			Registered:     true,
			MutablePolicy:  "flag_on_change", // NOT "block_on_change" -> requires admin
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if result.Allowed {
		t.Error("Expected denied for mutable source by non-admin, got allowed")
	}
	found := false
	for _, reason := range result.DenyReasons {
		if reason == "mutable_source_requires_admin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected deny reason 'mutable_source_requires_admin', got %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_MutableSourceAdmin verifies that an admin identity
// can access mutable data sources.
func TestEvaluateDataSourcePolicy_MutableSourceAdmin(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/admin/security-officer",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/mutable-data",
			Registered:     true,
			MutablePolicy:  "flag_on_change",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("Expected allowed for mutable source by admin, got denied: %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_UnregisteredHighRisk verifies that unregistered
// data sources are blocked for high-risk sessions (risk_score > 5).
func TestEvaluateDataSourcePolicy_UnregisteredHighRisk(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 7.5},
		DataSource: &DataSourceInput{
			URI:            "https://unknown-external-site.example.com/data",
			Registered:     false,
			MutablePolicy:  "",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if result.Allowed {
		t.Error("Expected denied for unregistered source in high-risk session, got allowed")
	}
	found := false
	for _, reason := range result.DenyReasons {
		if reason == "unregistered_high_risk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected deny reason 'unregistered_high_risk', got %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_UnregisteredLowRisk verifies that unregistered
// data sources are allowed for low-risk sessions (risk_score <= 5).
func TestEvaluateDataSourcePolicy_UnregisteredLowRisk(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 3.0},
		DataSource: &DataSourceInput{
			URI:            "https://unknown-external-site.example.com/data",
			Registered:     false,
			MutablePolicy:  "",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("Expected allowed for unregistered source in low-risk session, got denied: %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_FailClosedNoPolicyLoaded verifies fail-closed
// behavior when the data source policy is not loaded.
func TestEvaluateDataSourcePolicy_FailClosedNoPolicyLoaded(t *testing.T) {
	tmpDir := t.TempDir()
	// Only write MCP policy, no data source policy
	if err := os.WriteFile(filepath.Join(tmpDir, "mcp_policy.rego"), []byte(mcpPolicyStub), 0644); err != nil {
		t.Fatalf("Failed to write MCP policy: %v", err)
	}

	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/admin/security-officer",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/test",
			Registered:     true,
			MutablePolicy:  "block_on_change",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("Should not error (fail closed gracefully): %v", err)
	}
	if result.Allowed {
		t.Error("Expected fail-closed (deny) when data source policy not loaded")
	}
	if len(result.DenyReasons) == 0 {
		t.Error("Expected deny reasons for fail-closed")
	}
}

// TestEvaluateDataSourcePolicy_BoundaryRiskScore verifies behavior at the exact
// risk_score boundary of 5.
func TestEvaluateDataSourcePolicy_BoundaryRiskScore(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tests := []struct {
		name      string
		riskScore float64
		wantAllow bool
	}{
		{"risk_score_exactly_5_allowed", 5.0, true},
		{"risk_score_5.01_denied", 5.01, false},
		{"risk_score_4.99_allowed", 4.99, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
				Tool:     "read",
				Action:   "execute",
				Session:  SessionInput{RiskScore: tt.riskScore},
				DataSource: &DataSourceInput{
					URI:            "https://unregistered.example.com/data",
					Registered:     false,
					MutablePolicy:  "",
					ContentChanged: false,
				},
			}

			result, err := engine.EvaluateDataSourcePolicy(input)
			if err != nil {
				t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
			}
			if result.Allowed != tt.wantAllow {
				t.Errorf("Expected allowed=%v for risk_score=%.2f, got %v (reasons: %v)",
					tt.wantAllow, tt.riskScore, result.Allowed, result.DenyReasons)
			}
		})
	}
}

// TestEvaluateDataSourcePolicy_GlobPatternMatching verifies that glob patterns
// in grants work correctly for both SPIFFE IDs and URIs.
func TestEvaluateDataSourcePolicy_GlobPatternMatching(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	tests := []struct {
		name      string
		spiffeID  string
		uri       string
		wantAllow bool
	}{
		{
			name:      "wildcard_spiffe_match",
			spiffeID:  "spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev",
			uri:       "https://gist.github.com/abc123",
			wantAllow: true,
		},
		{
			name:      "wildcard_spiffe_no_match",
			spiffeID:  "spiffe://poc.local/agents/mcp-client/unauthorized/dev",
			uri:       "https://gist.github.com/abc123",
			wantAllow: false,
		},
		{
			name:      "admin_full_access",
			spiffeID:  "spiffe://poc.local/admin/ops",
			uri:       "https://private-internal-api.example.com/data",
			wantAllow: true,
		},
		{
			name:      "gateway_full_access",
			spiffeID:  "spiffe://poc.local/gateways/precinct-gateway/dev",
			uri:       "https://any-uri.example.com/anything",
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := OPAInput{
				SPIFFEID: tt.spiffeID,
				Tool:     "read",
				Action:   "execute",
				Session:  SessionInput{RiskScore: 0.1},
				DataSource: &DataSourceInput{
					URI:            tt.uri,
					Registered:     true,
					MutablePolicy:  "block_on_change",
					ContentChanged: false,
				},
			}

			result, err := engine.EvaluateDataSourcePolicy(input)
			if err != nil {
				t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
			}
			if result.Allowed != tt.wantAllow {
				t.Errorf("Expected allowed=%v for SPIFFE=%s URI=%s, got %v (reasons: %v)",
					tt.wantAllow, tt.spiffeID, tt.uri, result.Allowed, result.DenyReasons)
			}
		})
	}
}

// TestEvaluateDataSourcePolicy_BlockOnChangeMutablePolicy verifies that
// block_on_change is treated as the safe default (no admin required).
func TestEvaluateDataSourcePolicy_BlockOnChangeMutablePolicy(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Non-admin with block_on_change policy should be allowed
	input := OPAInput{
		SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		Tool:     "read",
		Action:   "execute",
		Session:  SessionInput{RiskScore: 0.1},
		DataSource: &DataSourceInput{
			URI:            "https://gist.github.com/safe-data",
			Registered:     true,
			MutablePolicy:  "block_on_change",
			ContentChanged: false,
		},
	}

	result, err := engine.EvaluateDataSourcePolicy(input)
	if err != nil {
		t.Fatalf("EvaluateDataSourcePolicy error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("Expected allowed for block_on_change by non-admin, got denied: %v", result.DenyReasons)
	}
}

// TestEvaluateDataSourcePolicy_Integration is a comprehensive integration test
// that exercises the full OPA engine with data source policy, grants data file,
// and the embedded evaluator -- no mocks.
func TestEvaluateDataSourcePolicy_Integration(t *testing.T) {
	tmpDir := setupDataSourcePolicyDir(t)
	engine, err := NewOPAEngine(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create OPA engine: %v", err)
	}
	defer func() { _ = engine.Close() }()

	// Scenario 1: Researcher accesses registered gist -> ALLOW
	t.Run("researcher_accesses_registered_gist", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 0.2},
			DataSource: &DataSourceInput{
				URI:            "https://gist.github.com/user/research-data",
				Registered:     true,
				MutablePolicy:  "block_on_change",
				ContentChanged: false,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Scenario 1 FAILED: researcher should access registered gist, denied: %v", result.DenyReasons)
		}
	})

	// Scenario 2: Unauthorized agent accesses registered gist -> DENY
	t.Run("unauthorized_agent_denied_registered_gist", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/rogue-agent/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 0.1},
			DataSource: &DataSourceInput{
				URI:            "https://gist.github.com/user/secret-data",
				Registered:     true,
				MutablePolicy:  "block_on_change",
				ContentChanged: false,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if result.Allowed {
			t.Error("Scenario 2 FAILED: unauthorized agent should be denied access to registered gist")
		}
	})

	// Scenario 3: Non-admin accesses mutable source -> DENY
	t.Run("non_admin_denied_mutable_source", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 0.1},
			DataSource: &DataSourceInput{
				URI:            "https://gist.github.com/user/mutable-data",
				Registered:     true,
				MutablePolicy:  "allow",
				ContentChanged: true,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if result.Allowed {
			t.Error("Scenario 3 FAILED: non-admin should be denied mutable source")
		}
		hasMutableReason := false
		for _, r := range result.DenyReasons {
			if r == "mutable_source_requires_admin" {
				hasMutableReason = true
				break
			}
		}
		if !hasMutableReason {
			t.Errorf("Expected 'mutable_source_requires_admin' deny reason, got: %v", result.DenyReasons)
		}
	})

	// Scenario 4: Admin accesses mutable source -> ALLOW
	t.Run("admin_allowed_mutable_source", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/admin/security-officer",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 0.1},
			DataSource: &DataSourceInput{
				URI:            "https://gist.github.com/user/mutable-data",
				Registered:     true,
				MutablePolicy:  "allow",
				ContentChanged: true,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Scenario 4 FAILED: admin should access mutable source, denied: %v", result.DenyReasons)
		}
	})

	// Scenario 5: High-risk session + unregistered source -> DENY
	t.Run("high_risk_session_denied_unregistered", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 8.0},
			DataSource: &DataSourceInput{
				URI:            "https://malicious-site.example.com/payload",
				Registered:     false,
				MutablePolicy:  "",
				ContentChanged: false,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if result.Allowed {
			t.Error("Scenario 5 FAILED: high-risk session should be denied unregistered source")
		}
		hasHighRiskReason := false
		for _, r := range result.DenyReasons {
			if r == "unregistered_high_risk" {
				hasHighRiskReason = true
				break
			}
		}
		if !hasHighRiskReason {
			t.Errorf("Expected 'unregistered_high_risk' deny reason, got: %v", result.DenyReasons)
		}
	})

	// Scenario 6: Low-risk session + unregistered source -> ALLOW
	t.Run("low_risk_session_allowed_unregistered", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 2.0},
			DataSource: &DataSourceInput{
				URI:            "https://new-external-site.example.com/data",
				Registered:     false,
				MutablePolicy:  "",
				ContentChanged: false,
			},
		}
		result, err := engine.EvaluateDataSourcePolicy(input)
		if err != nil {
			t.Fatalf("Error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Scenario 6 FAILED: low-risk session should allow unregistered source, denied: %v", result.DenyReasons)
		}
	})

	// Scenario 7: Main OPA evaluator still works with DataSource field (backward compat)
	t.Run("main_opa_evaluator_ignores_data_source", func(t *testing.T) {
		input := OPAInput{
			SPIFFEID: "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			Tool:     "read",
			Action:   "execute",
			Session:  SessionInput{RiskScore: 0.1},
			DataSource: &DataSourceInput{
				URI:        "https://gist.github.com/test",
				Registered: true,
			},
		}
		allowed, _, err := engine.Evaluate(input)
		if err != nil {
			t.Fatalf("Main Evaluate error: %v", err)
		}
		// The stub MCP policy allows everything
		if !allowed {
			t.Error("Main evaluator should still work with DataSource field present")
		}
	})
}
