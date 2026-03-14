package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileAdminStatusEndpoint(t *testing.T) {
	g := &Gateway{
		enforcementProfile: &enforcementProfileRuntime{
			Name:            enforcementProfileProdRegulatedHIPAA,
			Description:     "test regulated profile",
			StartupGateMode: "strict",
			RequiredControl: []string{"spiffe_mode=prod", "enforce_hipaa_prompt_safety_gate"},
			Runtime: map[string]string{
				"spiffe_mode":        "prod",
				"mcp_transport_mode": "mcp",
			},
			Controls: enforcementProfileControls{
				EnforceModelMediationGate: true,
				EnforceHIPAAPromptSafety:  true,
			},
			Conformance: enforcementProfileConformance{Status: "pass"},
			GeneratedAt: "2026-02-13T00:00:00Z",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/profiles/status", nil)
	rec := httptest.NewRecorder()
	g.adminProfilesHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	profile, ok := payload["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile object, got %T", payload["profile"])
	}
	if profile["name"] != enforcementProfileProdRegulatedHIPAA {
		t.Fatalf("expected profile name %q, got %v", enforcementProfileProdRegulatedHIPAA, profile["name"])
	}
}
