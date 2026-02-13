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
