package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestV24RuntimeDispatch_WiresAllEntrypointFamilies(t *testing.T) {
	gw, _ := newPhase3TestGateway(t)

	type routeCase struct {
		name      string
		dispatch  string
		method    string
		path      string
		body      string
		mustMatch int
	}

	tests := []routeCase{
		// Phase 3 plane runtime entrypoints
		{name: "ingress submit", dispatch: "plane", method: http.MethodPost, path: "/v1/ingress/submit", body: "{}", mustMatch: http.StatusBadRequest},
		{name: "context admit", dispatch: "plane", method: http.MethodPost, path: "/v1/context/admit", body: "{}", mustMatch: http.StatusBadRequest},
		{name: "model call", dispatch: "plane", method: http.MethodPost, path: "/v1/model/call", body: "{}", mustMatch: http.StatusBadRequest},
		{name: "tool execute", dispatch: "plane", method: http.MethodPost, path: "/v1/tool/execute", body: "{}", mustMatch: http.StatusBadRequest},
		{name: "loop check", dispatch: "plane", method: http.MethodPost, path: "/v1/loop/check", body: "{}", mustMatch: http.StatusBadRequest},

		// Connector authority runtime entrypoints
		{name: "connector report", dispatch: "connector", method: http.MethodGet, path: "/v1/connectors/report", mustMatch: http.StatusOK},
		{name: "connector status", dispatch: "connector", method: http.MethodGet, path: "/v1/connectors/status?connector_id=compose-webhook", mustMatch: http.StatusOK},

		// v2.4 admin runtime entrypoints
		{name: "ruleops summary", dispatch: "admin", method: http.MethodGet, path: "/admin/dlp/rulesets", mustMatch: http.StatusOK},
		{name: "approvals summary", dispatch: "admin", method: http.MethodGet, path: "/admin/approvals", mustMatch: http.StatusOK},
		{name: "breakglass status", dispatch: "admin", method: http.MethodGet, path: "/admin/breakglass/status", mustMatch: http.StatusOK},
		{name: "profiles status", dispatch: "admin", method: http.MethodGet, path: "/admin/profiles/status", mustMatch: http.StatusOK},
		{name: "loop runs", dispatch: "admin", method: http.MethodGet, path: "/admin/loop/runs", mustMatch: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.Header.Set("X-SPIFFE-ID", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev")
			rec := httptest.NewRecorder()

			var handled bool
			switch tc.dispatch {
			case "plane":
				handled = gw.handlePhase3PlaneEntry(rec, req)
			case "connector":
				handled = gw.handleConnectorAuthorityEntry(rec, req)
			case "admin":
				handled = gw.handleV24AdminEntry(rec, req)
			default:
				t.Fatalf("unsupported dispatch type %q", tc.dispatch)
			}

			if !handled {
				t.Fatalf("expected route %s to be handled by %s dispatcher", tc.path, tc.dispatch)
			}
			if rec.Code != tc.mustMatch {
				t.Fatalf("expected status %d for %s, got %d body=%s", tc.mustMatch, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestConfigFromEnv_WiresPhase3ControlPaths(t *testing.T) {
	t.Setenv("CAPABILITY_REGISTRY_V2_PATH", "/tmp/cap-registry-v2.yaml")
	t.Setenv("MODEL_PROVIDER_CATALOG_PATH", "/tmp/model-provider-catalog.v2.yaml")
	t.Setenv("MODEL_PROVIDER_CATALOG_PUBLIC_KEY", "/tmp/model-provider-catalog.pub")
	t.Setenv("GUARD_ARTIFACT_PATH", "/tmp/guard-model.bin")
	t.Setenv("GUARD_ARTIFACT_SHA256", "0123456789abcdef")
	t.Setenv("GUARD_ARTIFACT_SIGNATURE_PATH", "/tmp/guard-model.bin.sig")
	t.Setenv("GUARD_ARTIFACT_PUBLIC_KEY", "/tmp/guard-model.pub")
	t.Setenv("ENFORCEMENT_PROFILE", "prod_standard")

	cfg := ConfigFromEnv()

	if cfg.CapabilityRegistryV2Path != "/tmp/cap-registry-v2.yaml" {
		t.Fatalf("expected capability registry v2 path to be wired, got %q", cfg.CapabilityRegistryV2Path)
	}
	if cfg.ModelProviderCatalogPath != "/tmp/model-provider-catalog.v2.yaml" {
		t.Fatalf("expected model provider catalog path to be wired, got %q", cfg.ModelProviderCatalogPath)
	}
	if cfg.ModelProviderCatalogPublicKey != "/tmp/model-provider-catalog.pub" {
		t.Fatalf("expected model provider catalog public key path, got %q", cfg.ModelProviderCatalogPublicKey)
	}
	if cfg.GuardArtifactPath != "/tmp/guard-model.bin" {
		t.Fatalf("expected guard artifact path to be wired, got %q", cfg.GuardArtifactPath)
	}
	if cfg.GuardArtifactSHA256 != "0123456789abcdef" {
		t.Fatalf("expected guard artifact digest to be wired, got %q", cfg.GuardArtifactSHA256)
	}
	if cfg.GuardArtifactSignaturePath != "/tmp/guard-model.bin.sig" {
		t.Fatalf("expected guard artifact signature path to be wired, got %q", cfg.GuardArtifactSignaturePath)
	}
	if cfg.GuardArtifactPublicKey != "/tmp/guard-model.pub" {
		t.Fatalf("expected guard artifact public key path to be wired, got %q", cfg.GuardArtifactPublicKey)
	}
	if cfg.EnforcementProfile != "prod_standard" {
		t.Fatalf("expected enforcement profile override to be wired, got %q", cfg.EnforcementProfile)
	}
}
