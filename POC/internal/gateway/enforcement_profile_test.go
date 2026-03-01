package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStrictProfileTestConfig(profile string) *Config {
	return &Config{
		EnforcementProfile:            profile,
		SPIFFEMode:                    "prod",
		MCPTransportMode:              "mcp",
		UpstreamURL:                   "https://mcp-server.example.com/mcp",
		KeyDBURL:                      "redis://keydb:6379",
		EnforceModelMediationGate:     true,
		EnforceHIPAAPromptSafetyGate:  true,
		ApprovalSigningKey:            "prod-approval-signing-key-material-at-least-32",
		ToolRegistryConfigPath:        "/config/tool-registry.yaml",
		ToolRegistryPublicKey:         "/config/attestation-ed25519.pub",
		ModelProviderCatalogPath:      "/config/model-provider-catalog.v2.yaml",
		ModelProviderCatalogPublicKey: "/config/attestation-ed25519.pub",
		GuardArtifactPath:             "/config/guard-artifact.bin",
		GuardArtifactSHA256:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		GuardArtifactPublicKey:        "/config/attestation-ed25519.pub",
		EnforcementControlOverrides:   true,
	}
}

func TestResolveEnforcementProfile_DefaultDev(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           "",
		SPIFFEMode:                   "dev",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
	}

	profile, err := resolveEnforcementProfile(cfg)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	if profile.Name != enforcementProfileDev {
		t.Fatalf("expected profile=%q got=%q", enforcementProfileDev, profile.Name)
	}
	if profile.Conformance.Status != "pass" {
		t.Fatalf("expected conformance pass, got %q", profile.Conformance.Status)
	}
}

func TestResolveEnforcementProfile_ProdStandardFailsWhenMediationDisabled(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.EnforceModelMediationGate = false

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup gate failure")
	}
	if !strings.Contains(err.Error(), "enforce_model_mediation_gate must be true") {
		t.Fatalf("expected mediation gate error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_ProdHIPAAFailsWhenPromptSafetyDisabled(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdRegulatedHIPAA)
	cfg.EnforceHIPAAPromptSafetyGate = false

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict HIPAA profile startup gate failure")
	}
	if !strings.Contains(err.Error(), "enforce_hipaa_prompt_safety_gate must be true") {
		t.Fatalf("expected hipaa prompt safety error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWhenSPIFFEDevModeConfigured(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.SPIFFEMode = "dev"

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when spiffe_mode=dev")
	}
	if !strings.Contains(err.Error(), "spiffe_mode must be prod") {
		t.Fatalf("expected strict SPIFFE mode violation, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithoutApprovalSigningKey(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.ApprovalSigningKey = ""

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when approval signing key is missing")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be set") {
		t.Fatalf("expected approval signing key missing error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithWeakApprovalSigningKey(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.ApprovalSigningKey = "weak-key"

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when approval signing key is weak")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be at least") {
		t.Fatalf("expected approval signing key strength error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithoutKeyDBURL(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.KeyDBURL = ""

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when keydb_url is missing")
	}
	if !strings.Contains(err.Error(), "keydb_url must be set") {
		t.Fatalf("expected keydb_url requirement error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithoutRegistryPublicKey(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.ToolRegistryPublicKey = ""

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when tool registry key is missing")
	}
	if !strings.Contains(err.Error(), "tool_registry_public_key must be set") {
		t.Fatalf("expected tool registry key requirement error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictPassesWithStrongApprovalSigningKey(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)

	profile, err := resolveEnforcementProfile(cfg)
	if err != nil {
		t.Fatalf("expected strict profile to pass with strong signing key: %v", err)
	}
	if profile.Conformance.Status != "pass" {
		t.Fatalf("expected strict profile conformance pass, got %q", profile.Conformance.Status)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithPlaintextUpstreamURL(t *testing.T) {
	cfg := newStrictProfileTestConfig(enforcementProfileProdStandard)
	cfg.UpstreamURL = "http://mcp-server.example.com/mcp"

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure for plaintext upstream URL")
	}
	if !strings.Contains(err.Error(), "upstream_url must use https") {
		t.Fatalf("expected upstream https requirement error, got: %v", err)
	}
}

func TestEnforcementProfileExportWritesJSON(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           enforcementProfileDev,
		SPIFFEMode:                   "dev",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
	}
	profile, err := resolveEnforcementProfile(cfg)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}

	exportPath := filepath.Join(t.TempDir(), "profiles", "runtime-profile.json")
	if err := profile.export(exportPath); err != nil {
		t.Fatalf("export profile metadata: %v", err)
	}
	raw, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read export file: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal export payload: %v", err)
	}
	if payload["name"] != enforcementProfileDev {
		t.Fatalf("expected profile name %q in export, got %v", enforcementProfileDev, payload["name"])
	}
}
