package integration

import (
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
)

func TestProdProfileStartupFailsWhenMandatoryControlDisabled(t *testing.T) {
	cfg := &gateway.Config{
		Port:                         0,
		UpstreamURL:                  "http://localhost:8080",
		SPIFFEMode:                   "prod",
		MCPTransportMode:             "mcp",
		EnforcementProfile:           "prod_standard",
		EnforceModelMediationGate:    false, // required by prod profiles
		EnforceHIPAAPromptSafetyGate: true,
		ProfileMetadataExportPath:    "",
		EnforcementControlOverrides:  true,
	}

	_, err := gateway.New(cfg)
	if err == nil {
		t.Fatal("expected startup failure when mediation gate is disabled in prod profile")
	}
	if !strings.Contains(err.Error(), "enforce_model_mediation_gate must be true") {
		t.Fatalf("expected mandatory-control violation, got: %v", err)
	}
}
