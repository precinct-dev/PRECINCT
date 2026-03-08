package middleware

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestResolvePrincipalRole(t *testing.T) {
	const trustDomain = "poc.local"

	tests := []struct {
		name               string
		spiffeID           string
		trustDomain        string
		authMethod         string
		expectedLevel      int
		expectedRole       string
		expectedCaps       []string
		expectedDomain     string
		expectedAuthMethod string
	}{
		{
			name:               "Level0_System",
			spiffeID:           "spiffe://poc.local/system/gateway",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      0,
			expectedRole:       "system",
			expectedCaps:       []string{"admin", "read", "write", "execute", "delegate"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "Level1_Owner",
			spiffeID:           "spiffe://poc.local/owner/user1",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      1,
			expectedRole:       "owner",
			expectedCaps:       []string{"admin", "read", "write", "execute", "delegate"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "Level2_DelegatedAdmin",
			spiffeID:           "spiffe://poc.local/delegated/admin1",
			trustDomain:        trustDomain,
			authMethod:         "token",
			expectedLevel:      2,
			expectedRole:       "delegated_admin",
			expectedCaps:       []string{"read", "write", "execute", "delegate"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "token",
		},
		{
			name:               "Level3_Agent",
			spiffeID:           "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      3,
			expectedRole:       "agent",
			expectedCaps:       []string{"read", "write", "execute"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "Level4_ExternalUser",
			spiffeID:           "spiffe://poc.local/external/webhook",
			trustDomain:        trustDomain,
			authMethod:         "header_declared",
			expectedLevel:      4,
			expectedRole:       "external_user",
			expectedCaps:       []string{"read"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "header_declared",
		},
		{
			name:               "Level5_EmptyID",
			spiffeID:           "",
			trustDomain:        trustDomain,
			authMethod:         "header_declared",
			expectedLevel:      5,
			expectedRole:       "anonymous",
			expectedCaps:       []string{},
			expectedDomain:     "",
			expectedAuthMethod: "header_declared",
		},
		{
			name:               "Level5_UnknownPrefix",
			spiffeID:           "spiffe://poc.local/unknown/foo",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      5,
			expectedRole:       "anonymous",
			expectedCaps:       []string{},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "Level5_WrongTrustDomain",
			spiffeID:           "spiffe://other.domain/agents/foo",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      5,
			expectedRole:       "anonymous",
			expectedCaps:       []string{},
			expectedDomain:     "other.domain",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "Level5_InvalidScheme",
			spiffeID:           "https://poc.local/agents/foo",
			trustDomain:        trustDomain,
			authMethod:         "token",
			expectedLevel:      5,
			expectedRole:       "anonymous",
			expectedCaps:       []string{},
			expectedDomain:     "",
			expectedAuthMethod: "token",
		},
		{
			name:               "Level3_AgentDeepPath",
			spiffeID:           "spiffe://poc.local/agents/some/deep/nested/path",
			trustDomain:        trustDomain,
			authMethod:         "mtls_svid",
			expectedLevel:      3,
			expectedRole:       "agent",
			expectedCaps:       []string{"read", "write", "execute"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "mtls_svid",
		},
		{
			name:               "AuthMethodPassthrough",
			spiffeID:           "spiffe://poc.local/owner/user1",
			trustDomain:        trustDomain,
			authMethod:         "custom_auth_method",
			expectedLevel:      1,
			expectedRole:       "owner",
			expectedCaps:       []string{"admin", "read", "write", "execute", "delegate"},
			expectedDomain:     "poc.local",
			expectedAuthMethod: "custom_auth_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			role := ResolvePrincipalRole(tt.spiffeID, tt.trustDomain, tt.authMethod)

			if role.Level != tt.expectedLevel {
				t.Errorf("Level: got %d, want %d", role.Level, tt.expectedLevel)
			}
			if role.Role != tt.expectedRole {
				t.Errorf("Role: got %q, want %q", role.Role, tt.expectedRole)
			}
			if role.TrustDomain != tt.expectedDomain {
				t.Errorf("TrustDomain: got %q, want %q", role.TrustDomain, tt.expectedDomain)
			}
			if role.AuthMethod != tt.expectedAuthMethod {
				t.Errorf("AuthMethod: got %q, want %q", role.AuthMethod, tt.expectedAuthMethod)
			}

			// Compare capabilities
			if len(role.Capabilities) != len(tt.expectedCaps) {
				t.Errorf("Capabilities length: got %d, want %d (got %v, want %v)",
					len(role.Capabilities), len(tt.expectedCaps), role.Capabilities, tt.expectedCaps)
			} else {
				for i, cap := range tt.expectedCaps {
					if role.Capabilities[i] != cap {
						t.Errorf("Capabilities[%d]: got %q, want %q", i, role.Capabilities[i], cap)
					}
				}
			}
		})
	}
}

// TestResolvePrincipalRole_CapabilitiesIsolation verifies that modifying the
// returned capabilities slice does not affect subsequent calls (no shared
// backing array).
func TestResolvePrincipalRole_CapabilitiesIsolation(t *testing.T) {
	role1 := ResolvePrincipalRole("spiffe://poc.local/owner/user1", "poc.local", "mtls_svid")
	role1.Capabilities[0] = "MUTATED"

	role2 := ResolvePrincipalRole("spiffe://poc.local/owner/user2", "poc.local", "mtls_svid")
	if role2.Capabilities[0] != "admin" {
		t.Errorf("Capabilities isolation broken: got %q, want %q", role2.Capabilities[0], "admin")
	}
}

// TestResolvePrincipalRole_OwnerCapabilities verifies owner gets the full
// 5-capability set: admin, read, write, execute, delegate.
func TestResolvePrincipalRole_OwnerCapabilities(t *testing.T) {
	role := ResolvePrincipalRole("spiffe://poc.local/owner/user1", "poc.local", "mtls_svid")
	expected := []string{"admin", "read", "write", "execute", "delegate"}
	if len(role.Capabilities) != len(expected) {
		t.Fatalf("Owner capabilities length: got %d, want %d", len(role.Capabilities), len(expected))
	}
	for i, cap := range expected {
		if role.Capabilities[i] != cap {
			t.Errorf("Owner capability[%d]: got %q, want %q", i, role.Capabilities[i], cap)
		}
	}
}

// TestResolvePrincipalRole_ExternalCapabilities verifies external_user gets
// only ["read"].
func TestResolvePrincipalRole_ExternalCapabilities(t *testing.T) {
	role := ResolvePrincipalRole("spiffe://poc.local/external/webhook", "poc.local", "mtls_svid")
	if len(role.Capabilities) != 1 || role.Capabilities[0] != "read" {
		t.Errorf("External capabilities: got %v, want [read]", role.Capabilities)
	}
}

// TestResolvePrincipalRole_AnonymousEmptyCapabilities verifies anonymous role
// returns an empty (non-nil) capabilities slice.
func TestResolvePrincipalRole_AnonymousEmptyCapabilities(t *testing.T) {
	role := ResolvePrincipalRole("", "poc.local", "mtls_svid")
	if role.Capabilities == nil {
		t.Error("Anonymous capabilities should be empty slice, not nil")
	}
	if len(role.Capabilities) != 0 {
		t.Errorf("Anonymous capabilities length: got %d, want 0", len(role.Capabilities))
	}
}

// --- Integration test ---

// gatewayConfig is a minimal struct to parse the SPIFFETrustDomain from the
// gateway configuration file. This avoids importing the gateway package (which
// would create a circular dependency) while still testing against real config.
type gatewayConfig struct {
	SPIFFETrustDomain string `yaml:"spiffe_trust_domain"`
}

// TestResolvePrincipalRole_Integration loads the real trust domain from
// POC/config/gateway.yaml (or falls back to the default "poc.local") and
// resolves a realistic SPIFFE ID pattern used by the demo agent.
func TestResolvePrincipalRole_Integration(t *testing.T) {
	// Try to load gateway.yaml for the real trust domain.
	trustDomain := "poc.local" // default

	configPaths := []string{
		"../../../config/gateway.yaml",
		"../../../../config/gateway.yaml",
	}
	for _, p := range configPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg gatewayConfig
		if err := yaml.Unmarshal(data, &cfg); err == nil && cfg.SPIFFETrustDomain != "" {
			trustDomain = cfg.SPIFFETrustDomain
		}
		break
	}

	// The demo agent SPIFFE ID used across the POC.
	agentSPIFFEID := "spiffe://" + trustDomain + "/agents/mcp-client/dspy-researcher/dev"

	role := ResolvePrincipalRole(agentSPIFFEID, trustDomain, "mtls_svid")

	if role.Level != 3 {
		t.Errorf("Integration: agent level got %d, want 3", role.Level)
	}
	if role.Role != "agent" {
		t.Errorf("Integration: agent role got %q, want %q", role.Role, "agent")
	}
	if role.TrustDomain != trustDomain {
		t.Errorf("Integration: trust domain got %q, want %q", role.TrustDomain, trustDomain)
	}
	if role.AuthMethod != "mtls_svid" {
		t.Errorf("Integration: auth method got %q, want %q", role.AuthMethod, "mtls_svid")
	}

	// Verify capabilities are exactly read, write, execute (no admin, no delegate).
	expectedCaps := []string{"read", "write", "execute"}
	if len(role.Capabilities) != len(expectedCaps) {
		t.Fatalf("Integration: capabilities length got %d, want %d", len(role.Capabilities), len(expectedCaps))
	}
	for i, cap := range expectedCaps {
		if role.Capabilities[i] != cap {
			t.Errorf("Integration: capability[%d] got %q, want %q", i, role.Capabilities[i], cap)
		}
	}

	// Verify that a system-level identity in the same domain resolves to level 0.
	systemID := "spiffe://" + trustDomain + "/system/gateway"
	systemRole := ResolvePrincipalRole(systemID, trustDomain, "mtls_svid")
	if systemRole.Level != 0 {
		t.Errorf("Integration: system level got %d, want 0", systemRole.Level)
	}

	// Verify cross-domain is rejected to anonymous.
	crossDomainID := "spiffe://evil.corp/agents/mcp-client/backdoor"
	crossRole := ResolvePrincipalRole(crossDomainID, trustDomain, "mtls_svid")
	if crossRole.Level != 5 {
		t.Errorf("Integration: cross-domain level got %d, want 5", crossRole.Level)
	}
	if crossRole.Role != "anonymous" {
		t.Errorf("Integration: cross-domain role got %q, want %q", crossRole.Role, "anonymous")
	}
}
