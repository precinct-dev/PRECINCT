package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func TestRuleOpsLifecycle_UnsignedPromotionFailsSignedPromotionSucceeds(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)

	rulesetID := fmt.Sprintf("itest-ruleops-%d", time.Now().UnixNano())
	createBody := map[string]any{
		"ruleset_id": rulesetID,
		"created_by": "integration@test",
		"content": map[string]any{
			"rules": []any{
				map[string]any{"id": "deny-creds", "action": "deny"},
			},
		},
	}

	code, body := ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/create", createBody)
	if code != http.StatusOK {
		t.Fatalf("create expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/validate", map[string]any{"ruleset_id": rulesetID})
	if code != http.StatusOK {
		t.Fatalf("validate expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/approve", map[string]any{
		"ruleset_id":  rulesetID,
		"approved_by": "security@test",
	})
	if code != http.StatusOK {
		t.Fatalf("approve expected 200, got %d body=%v", code, body)
	}
	expectedSig := nestedRuleOpsField(body, "record", "expected_signature")
	if expectedSig == "" {
		t.Fatalf("approve response missing expected signature: %v", body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": rulesetID,
		"mode":       "active",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("unsigned promote expected 400, got %d body=%v", code, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/sign", map[string]any{
		"ruleset_id": rulesetID,
		"signature":  expectedSig,
	})
	if code != http.StatusOK {
		t.Fatalf("sign expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": rulesetID,
		"mode":       "canary",
	})
	if code != http.StatusOK {
		t.Fatalf("canary promote expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/promote", map[string]any{
		"ruleset_id": rulesetID,
		"mode":       "active",
	})
	if code != http.StatusOK {
		t.Fatalf("signed promote expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsGet(t, baseURL+"/admin/dlp/rulesets/active")
	if code != http.StatusOK {
		t.Fatalf("active endpoint expected 200, got %d body=%v", code, body)
	}
	if got := nestedRuleOpsField(body, "active", "ruleset_id"); got != rulesetID {
		t.Fatalf("expected active ruleset %q, got %q body=%v", rulesetID, got, body)
	}

	code, body = ruleOpsPost(t, baseURL+"/admin/dlp/rulesets/rollback", map[string]any{"ruleset_id": rulesetID})
	if code != http.StatusOK {
		t.Fatalf("rollback expected 200, got %d body=%v", code, body)
	}

	code, body = ruleOpsGet(t, baseURL+"/admin/dlp/rulesets/active")
	if code != http.StatusOK {
		t.Fatalf("active endpoint after rollback expected 200, got %d body=%v", code, body)
	}
	if got := nestedRuleOpsField(body, "active", "ruleset_id"); got == rulesetID {
		t.Fatalf("expected active ruleset to move off rolled-back id %q body=%v", rulesetID, body)
	}
}

func newRuleOpsTestServerURL(t *testing.T) string {
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
	t.Cleanup(srv.Close)
	return srv.URL
}

func ruleOpsPost(t *testing.T, url string, payload map[string]any) (int, map[string]any) {
	t.Helper()
	return ruleOpsPostAs(t, url, payload, adminSPIFFEIDForTest())
}

func ruleOpsPostAs(t *testing.T, url string, payload map[string]any, spiffeID string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SPIFFE-ID", spiffeID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s failed: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func ruleOpsGet(t *testing.T, url string) (int, map[string]any) {
	t.Helper()
	return ruleOpsGetAs(t, url, adminSPIFFEIDForTest())
}

func ruleOpsGetAs(t *testing.T, url string, spiffeID string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-SPIFFE-ID", spiffeID)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s failed: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func nestedRuleOpsField(root map[string]any, parent, key string) string {
	v, ok := root[parent]
	if !ok {
		return ""
	}
	nested, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	out, _ := nested[key].(string)
	return out
}
