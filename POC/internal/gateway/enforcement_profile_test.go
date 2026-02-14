package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	cfg := &Config{
		EnforcementProfile:           enforcementProfileProdStandard,
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    false,
		EnforceHIPAAPromptSafetyGate: true,
		EnforcementControlOverrides:  true,
	}

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup gate failure")
	}
	if !strings.Contains(err.Error(), "enforce_model_mediation_gate must be true") {
		t.Fatalf("expected mediation gate error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_ProdHIPAAFailsWhenPromptSafetyDisabled(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           enforcementProfileProdRegulatedHIPAA,
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: false,
		EnforcementControlOverrides:  true,
	}

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict HIPAA profile startup gate failure")
	}
	if !strings.Contains(err.Error(), "enforce_hipaa_prompt_safety_gate must be true") {
		t.Fatalf("expected hipaa prompt safety error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithoutApprovalSigningKey(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           enforcementProfileProdStandard,
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
		ApprovalSigningKey:           "",
		EnforcementControlOverrides:  true,
	}

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when approval signing key is missing")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be set") {
		t.Fatalf("expected approval signing key missing error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictFailsWithWeakApprovalSigningKey(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           enforcementProfileProdStandard,
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
		ApprovalSigningKey:           "weak-key",
		EnforcementControlOverrides:  true,
	}

	_, err := resolveEnforcementProfile(cfg)
	if err == nil {
		t.Fatal("expected strict profile startup failure when approval signing key is weak")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be at least") {
		t.Fatalf("expected approval signing key strength error, got: %v", err)
	}
}

func TestResolveEnforcementProfile_StrictPassesWithStrongApprovalSigningKey(t *testing.T) {
	cfg := &Config{
		EnforcementProfile:           enforcementProfileProdStandard,
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforceModelMediationGate:    true,
		EnforceHIPAAPromptSafetyGate: true,
		ApprovalSigningKey:           "prod-approval-signing-key-material-at-least-32",
		EnforcementControlOverrides:  true,
	}

	profile, err := resolveEnforcementProfile(cfg)
	if err != nil {
		t.Fatalf("expected strict profile to pass with strong signing key: %v", err)
	}
	if profile.Conformance.Status != "pass" {
		t.Fatalf("expected strict profile conformance pass, got %q", profile.Conformance.Status)
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
