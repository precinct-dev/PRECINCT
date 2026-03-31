package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/gateway/middleware"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func strictBypassContractTestConfig(t *testing.T) *gateway.Config {
	t.Helper()
	projectRoot := testutil.ProjectRoot()
	return &gateway.Config{
		Port:                          0,
		UpstreamURL:                   "https://mcp-server.example.com/mcp",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		OPAPolicyPublicKey:            filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		ToolRegistryPublicKey:         filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
		ModelProviderCatalogPath:      filepath.Join(projectRoot, "config", "model-provider-catalog.v2.yaml"),
		ModelProviderCatalogPublicKey: filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
		GuardArtifactPath:             filepath.Join(projectRoot, "config", "guard-artifact.bin"),
		GuardArtifactSHA256:           "8232540100ebde3b5682c2b47d1eee50764f6dadca3842400157061656fc95a3",
		GuardArtifactPublicKey:        filepath.Join(projectRoot, "config", "attestation-ed25519.pub"),
		DestinationsConfigPath:        filepath.Join(projectRoot, "config", "destinations.yaml"),
		RiskThresholdsPath:            filepath.Join(projectRoot, "config", "risk_thresholds.yaml"),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024,
		SPIFFEMode:                    "prod",
		MCPTransportMode:              "mcp",
		EnforcementProfile:            "prod_standard",
		ApprovalSigningKey:            "prod-approval-signing-key-material-at-least-32",
		AdminAuthzAllowedSPIFFEIDs:    []string{"spiffe://poc.local/admin/security"},
		KeyDBURL:                      "redis://keydb:6379",
	}
}

func TestStrictStartupFailsWhenOPABypassContractMissingChecks(t *testing.T) {
	restore := middleware.SetOPABypassContractsForTest([]middleware.OPABypassContract{
		{
			ID:          "broken_missing_checks",
			ExactPaths:  []string{"/v1/model/call"},
			ProbePath:   "/v1/model/call",
			ProbeMethod: http.MethodPost,
		},
	})
	defer restore()

	_, err := gateway.New(strictBypassContractTestConfig(t))
	if err == nil {
		t.Fatal("expected strict startup to fail when bypass contract omits compensating checks")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "opa bypass contract validation failed") {
		t.Fatalf("expected strict startup failure due bypass contract validation, got: %v", err)
	}
}

func TestOPABypassRoutes_DenyByDefaultForMissingOrInvalidIdentity(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)

	for _, contract := range middleware.ListOPABypassContracts() {
		method := contract.ProbeMethod
		if strings.TrimSpace(method) == "" {
			method = http.MethodPost
		}

		t.Run(contract.ID+"/missing_identity", func(t *testing.T) {
			status, body := doBypassProbeRequest(t, baseURL, contract, method, "")
			if status != http.StatusUnauthorized {
				t.Fatalf("expected 401 for missing identity on %s %s, got %d body=%v", method, contract.ProbePath, status, body)
			}
			if got, _ := body["code"].(string); got != middleware.ErrAuthMissingIdentity {
				t.Fatalf("expected code=%q for missing identity, got %q body=%v", middleware.ErrAuthMissingIdentity, got, body)
			}
		})

		t.Run(contract.ID+"/invalid_identity", func(t *testing.T) {
			status, body := doBypassProbeRequest(t, baseURL, contract, method, "not-a-spiffe-id")
			if status != http.StatusUnauthorized {
				t.Fatalf("expected 401 for invalid identity on %s %s, got %d body=%v", method, contract.ProbePath, status, body)
			}
			if got, _ := body["code"].(string); got != middleware.ErrAuthInvalidIdentity {
				t.Fatalf("expected code=%q for invalid identity, got %q body=%v", middleware.ErrAuthInvalidIdentity, got, body)
			}
		})
	}
}

func doBypassProbeRequest(t *testing.T, baseURL string, contract middleware.OPABypassContract, method, spiffeID string) (int, map[string]any) {
	t.Helper()

	var bodyReader *bytes.Reader
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		bodyReader = bytes.NewReader([]byte(`{}`))
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, baseURL+contract.ProbePath, bodyReader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if bodyReader.Len() > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if spiffeID != "" {
		req.Header.Set("X-SPIFFE-ID", spiffeID)
	}
	if contract.RequiresWebSocketUpgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
