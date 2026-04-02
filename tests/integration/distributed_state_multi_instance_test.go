package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func newRuleOpsTestServerURLWithKeyDB(t *testing.T, keydbURL string) string {
	t.Helper()

	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations config: %v", err)
	}

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "dev",
		AdminAuthzAllowedSPIFFEIDs: []string{
			adminSPIFFEIDForTest(),
		},
		DestinationsConfigPath: destinationsPath,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
		KeyDBURL:               keydbURL,
		KeyDBPoolMin:           1,
		KeyDBPoolMax:           5,
		SessionTTL:             3600,
		ApprovalSigningKey:     "distributed-approval-signing-key-material-12345",
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	controlHandler := gw.ControlHandler()
	dataHandler := gw.Handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin", strings.HasPrefix(r.URL.Path, "/admin/"), strings.HasPrefix(r.URL.Path, "/v1/connectors/"):
			controlHandler.ServeHTTP(w, r)
		default:
			dataHandler.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(func() {
		srv.Close()
		_ = gw.Close()
	})
	return srv.URL
}

func TestDistributedState_MultiInstanceApprovalAndBreakGlass(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	keydbURL := "redis://" + mr.Addr()
	baseA := newRuleOpsTestServerURLWithKeyDB(t, keydbURL)
	baseB := newRuleOpsTestServerURLWithKeyDB(t, keydbURL)

	requestCode, requestBody := ruleOpsPost(t, baseA+"/admin/approvals/request", map[string]any{
		"scope": map[string]any{
			"action":          "model.call",
			"resource":        "gpt-4o",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"session_id":      "dist-it-session",
		},
		"requested_by": "integration@test",
		"ttl_seconds":  120,
	})
	if requestCode != http.StatusOK {
		t.Fatalf("approval request expected 200, got %d body=%v", requestCode, requestBody)
	}
	record, ok := requestBody["record"].(map[string]any)
	if !ok {
		t.Fatalf("approval request missing record payload: %v", requestBody)
	}
	requestID, _ := record["request_id"].(string)
	if requestID == "" {
		t.Fatalf("approval request_id missing: %v", requestBody)
	}

	grantCode, grantBody := ruleOpsPost(t, baseA+"/admin/approvals/grant", map[string]any{
		"request_id":  requestID,
		"approved_by": "security@test",
	})
	if grantCode != http.StatusOK {
		t.Fatalf("approval grant expected 200, got %d body=%v", grantCode, grantBody)
	}
	token, _ := grantBody["capability_token"].(string)
	if token == "" {
		t.Fatalf("approval token missing from grant response: %v", grantBody)
	}

	consumeCode, consumeBody := ruleOpsPost(t, baseB+"/admin/approvals/consume", map[string]any{
		"capability_token": token,
		"scope": map[string]any{
			"action":          "model.call",
			"resource":        "gpt-4o",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"session_id":      "dist-it-session",
		},
	})
	if consumeCode != http.StatusOK {
		t.Fatalf("approval consume on second instance expected 200, got %d body=%v", consumeCode, consumeBody)
	}

	consumeAgainCode, consumeAgainBody := ruleOpsPost(t, baseA+"/admin/approvals/consume", map[string]any{
		"capability_token": token,
		"scope": map[string]any{
			"action":          "model.call",
			"resource":        "gpt-4o",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"session_id":      "dist-it-session",
		},
	})
	if consumeAgainCode != http.StatusConflict {
		t.Fatalf("second consume expected 409 conflict, got %d body=%v", consumeAgainCode, consumeAgainBody)
	}

	bgReqCode, bgReqBody := ruleOpsPost(t, baseA+"/admin/breakglass/request", map[string]any{
		"incident_id": "INC-DIST-IT-001",
		"scope": map[string]any{
			"action":          "model.call",
			"resource":        "gpt-4o",
			"actor_spiffe_id": "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		},
		"requested_by": "integration@test",
		"ttl_seconds":  120,
	})
	if bgReqCode != http.StatusOK {
		t.Fatalf("breakglass request expected 200, got %d body=%v", bgReqCode, bgReqBody)
	}
	bgRecord, ok := bgReqBody["record"].(map[string]any)
	if !ok {
		t.Fatalf("breakglass request missing record payload: %v", bgReqBody)
	}
	bgRequestID, _ := bgRecord["request_id"].(string)
	if bgRequestID == "" {
		t.Fatalf("breakglass request_id missing: %v", bgReqBody)
	}

	bgApproveA, bodyA := ruleOpsPost(t, baseA+"/admin/breakglass/approve", map[string]any{
		"request_id":  bgRequestID,
		"approved_by": "approver-a@test",
	})
	if bgApproveA != http.StatusOK {
		t.Fatalf("breakglass approve A expected 200, got %d body=%v", bgApproveA, bodyA)
	}
	bgApproveB, bodyB := ruleOpsPost(t, baseB+"/admin/breakglass/approve", map[string]any{
		"request_id":  bgRequestID,
		"approved_by": "approver-b@test",
	})
	if bgApproveB != http.StatusOK {
		t.Fatalf("breakglass approve B expected 200, got %d body=%v", bgApproveB, bodyB)
	}
	bgActivateCode, bgActivateBody := ruleOpsPost(t, baseB+"/admin/breakglass/activate", map[string]any{
		"request_id":   bgRequestID,
		"activated_by": "incident-commander@test",
	})
	if bgActivateCode != http.StatusOK {
		t.Fatalf("breakglass activate expected 200, got %d body=%v", bgActivateCode, bgActivateBody)
	}

	statusCode, statusBody := ruleOpsGet(t, baseA+"/admin/breakglass/status")
	if statusCode != http.StatusOK {
		t.Fatalf("breakglass status expected 200, got %d body=%v", statusCode, statusBody)
	}
	requestsRaw, ok := statusBody["requests"]
	if !ok {
		t.Fatalf("breakglass status missing requests field: %v", statusBody)
	}
	// Round-trip through JSON to normalize []any / map[string]any and check presence.
	raw, _ := json.Marshal(requestsRaw)
	var requests []map[string]any
	_ = json.Unmarshal(raw, &requests)

	foundActive := false
	for _, rec := range requests {
		id, _ := rec["request_id"].(string)
		status, _ := rec["status"].(string)
		if id == bgRequestID && status == "active" {
			foundActive = true
			break
		}
	}
	if !foundActive {
		t.Fatalf("expected active breakglass record %q in instance A status view, got %v", bgRequestID, requests)
	}
}
