package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// --- OC-t7go: PrincipalHeaders middleware tests ---

// TestPrincipalHeaders_Injection verifies that the PrincipalHeaders middleware
// injects the correct X-Precinct-Principal-* headers for each authority level.
func TestPrincipalHeaders_Injection(t *testing.T) {
	const trustDomain = "poc.local"

	tests := []struct {
		name           string
		spiffeID       string
		expectedLevel  int
		expectedRole   string
		expectedCaps   string
		expectedAuth   string
	}{
		{
			name:          "Level0_System",
			spiffeID:      "spiffe://poc.local/system/gateway",
			expectedLevel: 0,
			expectedRole:  "system",
			expectedCaps:  "admin,read,write,execute,delegate",
			expectedAuth:  "header_declared",
		},
		{
			name:          "Level1_Owner",
			spiffeID:      "spiffe://poc.local/owner/alice",
			expectedLevel: 1,
			expectedRole:  "owner",
			expectedCaps:  "admin,read,write,execute,delegate",
			expectedAuth:  "header_declared",
		},
		{
			name:          "Level2_Delegated",
			spiffeID:      "spiffe://poc.local/delegated/admin1",
			expectedLevel: 2,
			expectedRole:  "delegated_admin",
			expectedCaps:  "read,write,execute,delegate",
			expectedAuth:  "header_declared",
		},
		{
			name:          "Level3_Agent",
			spiffeID:      "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			expectedLevel: 3,
			expectedRole:  "agent",
			expectedCaps:  "read,write,execute",
			expectedAuth:  "header_declared",
		},
		{
			name:          "Level4_External",
			spiffeID:      "spiffe://poc.local/external/bob",
			expectedLevel: 4,
			expectedRole:  "external_user",
			expectedCaps:  "read",
			expectedAuth:  "header_declared",
		},
		{
			name:          "Level5_Anonymous",
			spiffeID:      "",
			expectedLevel: 5,
			expectedRole:  "anonymous",
			expectedCaps:  "",
			expectedAuth:  "header_declared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedHeaders http.Header
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				w.WriteHeader(http.StatusOK)
			})

			handler := PrincipalHeaders(inner, trustDomain, "dev")

			req := httptest.NewRequest("POST", "/mcp", nil)
			// Pre-set SPIFFE ID in context (simulating SPIFFEAuth middleware)
			ctx := WithSPIFFEID(req.Context(), tt.spiffeID)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if got := capturedHeaders.Get("X-Precinct-Principal-Level"); got != strconv.Itoa(tt.expectedLevel) {
				t.Errorf("X-Precinct-Principal-Level: got %q, want %q", got, strconv.Itoa(tt.expectedLevel))
			}
			if got := capturedHeaders.Get("X-Precinct-Principal-Role"); got != tt.expectedRole {
				t.Errorf("X-Precinct-Principal-Role: got %q, want %q", got, tt.expectedRole)
			}
			if got := capturedHeaders.Get("X-Precinct-Principal-Capabilities"); got != tt.expectedCaps {
				t.Errorf("X-Precinct-Principal-Capabilities: got %q, want %q", got, tt.expectedCaps)
			}
			if got := capturedHeaders.Get("X-Precinct-Auth-Method"); got != tt.expectedAuth {
				t.Errorf("X-Precinct-Auth-Method: got %q, want %q", got, tt.expectedAuth)
			}
		})
	}
}

// TestPrincipalHeaders_Stripping verifies that client-provided principal headers
// are stripped (anti-forgery) and replaced with gateway-computed values.
func TestPrincipalHeaders_Stripping(t *testing.T) {
	const trustDomain = "poc.local"

	var capturedHeaders http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	handler := PrincipalHeaders(inner, trustDomain, "dev")

	req := httptest.NewRequest("POST", "/mcp", nil)
	// Client forges owner-level headers
	req.Header.Set("X-Precinct-Principal-Level", "0")
	req.Header.Set("X-Precinct-Principal-Role", "system")
	req.Header.Set("X-Precinct-Principal-Capabilities", "admin,read,write,execute,delegate")
	req.Header.Set("X-Precinct-Auth-Method", "mtls_svid")

	// But the actual SPIFFE ID is external (level 4)
	ctx := WithSPIFFEID(req.Context(), "spiffe://poc.local/external/attacker")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify forged headers were stripped and replaced with correct values
	if got := capturedHeaders.Get("X-Precinct-Principal-Level"); got != "4" {
		t.Errorf("Forged level not overwritten: got %q, want %q", got, "4")
	}
	if got := capturedHeaders.Get("X-Precinct-Principal-Role"); got != "external_user" {
		t.Errorf("Forged role not overwritten: got %q, want %q", got, "external_user")
	}
	if got := capturedHeaders.Get("X-Precinct-Principal-Capabilities"); got != "read" {
		t.Errorf("Forged capabilities not overwritten: got %q, want %q", got, "read")
	}
	if got := capturedHeaders.Get("X-Precinct-Auth-Method"); got != "header_declared" {
		t.Errorf("Forged auth method not overwritten: got %q, want %q", got, "header_declared")
	}
}

// TestPrincipalHeaders_ProdAuthMethod verifies that prod mode sets authMethod
// to mtls_svid.
func TestPrincipalHeaders_ProdAuthMethod(t *testing.T) {
	var capturedHeaders http.Header
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	handler := PrincipalHeaders(inner, "poc.local", "prod")

	req := httptest.NewRequest("POST", "/mcp", nil)
	ctx := WithSPIFFEID(req.Context(), "spiffe://poc.local/owner/alice")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := capturedHeaders.Get("X-Precinct-Auth-Method"); got != "mtls_svid" {
		t.Errorf("Prod auth method: got %q, want %q", got, "mtls_svid")
	}
}

// TestPrincipalHeaders_ContextStorage verifies that PrincipalRole is stored in
// the request context and accessible via GetPrincipalRole.
func TestPrincipalHeaders_ContextStorage(t *testing.T) {
	var capturedRole PrincipalRole
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = GetPrincipalRole(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := PrincipalHeaders(inner, "poc.local", "dev")

	req := httptest.NewRequest("POST", "/mcp", nil)
	ctx := WithSPIFFEID(req.Context(), "spiffe://poc.local/owner/alice")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if capturedRole.Level != 1 {
		t.Errorf("Context PrincipalRole.Level: got %d, want 1", capturedRole.Level)
	}
	if capturedRole.Role != "owner" {
		t.Errorf("Context PrincipalRole.Role: got %q, want %q", capturedRole.Role, "owner")
	}
	if capturedRole.TrustDomain != "poc.local" {
		t.Errorf("Context PrincipalRole.TrustDomain: got %q, want %q", capturedRole.TrustDomain, "poc.local")
	}
}

// TestPrincipalHeaders_GetPrincipalRole_Default verifies that GetPrincipalRole
// returns a zero-value PrincipalRole when not set in context.
func TestPrincipalHeaders_GetPrincipalRole_Default(t *testing.T) {
	role := GetPrincipalRole(context.Background())
	if role.Level != 0 {
		t.Errorf("Default PrincipalRole.Level: got %d, want 0", role.Level)
	}
	if role.Role != "" {
		t.Errorf("Default PrincipalRole.Role: got %q, want empty", role.Role)
	}
}

// TestPrincipalHeaders_AuditEnrichment verifies that audit events include
// PrincipalLevel and PrincipalRole when PrincipalHeaders middleware runs
// before the audit middleware.
func TestPrincipalHeaders_AuditEnrichment(t *testing.T) {
	// Create a temp dir for audit files and policy/registry files
	tmpDir := t.TempDir()

	policyPath := filepath.Join(tmpDir, "policy.rego")
	registryPath := filepath.Join(tmpDir, "registry.yaml")
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	// Create minimal policy and registry files for the auditor
	if err := os.WriteFile(policyPath, []byte("package test"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, []byte("tools: []"), 0644); err != nil {
		t.Fatal(err)
	}

	auditor, err := NewAuditor(auditPath, policyPath, registryPath)
	if err != nil {
		t.Fatalf("NewAuditor: %v", err)
	}
	defer auditor.Close()

	// Build the middleware chain: AuditLog -> PrincipalHeaders -> inner
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := AuditLog(
		PrincipalHeaders(inner, "poc.local", "dev"),
		auditor,
	)

	req := httptest.NewRequest("POST", "/mcp", nil)
	ctx := WithSPIFFEID(req.Context(), "spiffe://poc.local/owner/alice")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Flush async writes
	auditor.Flush()

	// Read the audit file
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("no audit events found")
	}

	var event AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &event); err != nil {
		t.Fatalf("unmarshal audit event: %v", err)
	}

	if event.PrincipalLevel != 1 {
		t.Errorf("Audit PrincipalLevel: got %d, want 1", event.PrincipalLevel)
	}
	if event.PrincipalRole != "owner" {
		t.Errorf("Audit PrincipalRole: got %q, want %q", event.PrincipalRole, "owner")
	}
}

// --- OC-t7go: Integration test for PrincipalHeaders ---

// TestPrincipalHeaders_Integration verifies that different SPIFFE IDs produce
// correct principal levels when resolved through the full PrincipalHeaders
// middleware, using the real trust domain from config.
func TestPrincipalHeaders_Integration(t *testing.T) {
	// Load trust domain from config (same approach as the existing integration test)
	trustDomain := "poc.local"
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

	tests := []struct {
		name          string
		spiffeID      string
		expectedLevel int
		expectedRole  string
	}{
		{
			name:          "Owner",
			spiffeID:      "spiffe://" + trustDomain + "/owner/alice",
			expectedLevel: 1,
			expectedRole:  "owner",
		},
		{
			name:          "External",
			spiffeID:      "spiffe://" + trustDomain + "/external/bob",
			expectedLevel: 4,
			expectedRole:  "external_user",
		},
		{
			name:          "Anonymous_NoSPIFFE",
			spiffeID:      "",
			expectedLevel: 5,
			expectedRole:  "anonymous",
		},
		{
			name:          "Agent",
			spiffeID:      "spiffe://" + trustDomain + "/agents/mcp-client/dspy-researcher/dev",
			expectedLevel: 3,
			expectedRole:  "agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedHeaders http.Header
			var capturedRole PrincipalRole
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header.Clone()
				capturedRole = GetPrincipalRole(r.Context())
				w.WriteHeader(http.StatusOK)
			})

			handler := PrincipalHeaders(inner, trustDomain, "dev")

			req := httptest.NewRequest("POST", "/mcp", nil)
			ctx := WithSPIFFEID(req.Context(), tt.spiffeID)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify header
			gotLevel := capturedHeaders.Get("X-Precinct-Principal-Level")
			if gotLevel != strconv.Itoa(tt.expectedLevel) {
				t.Errorf("Header level: got %q, want %d", gotLevel, tt.expectedLevel)
			}

			// Verify context
			if capturedRole.Level != tt.expectedLevel {
				t.Errorf("Context level: got %d, want %d", capturedRole.Level, tt.expectedLevel)
			}
			if capturedRole.Role != tt.expectedRole {
				t.Errorf("Context role: got %q, want %q", capturedRole.Role, tt.expectedRole)
			}
		})
	}
}
