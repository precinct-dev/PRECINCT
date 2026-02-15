package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/agentic-security-poc/internal/testutil"
)

func TestEnforcementProfile_StrictStartupFailsFastWithoutApprovalSigningKey(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", testutil.ToolRegistryConfigPath())
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "")

	cfg := ConfigFromEnv()
	if cfg.ApprovalSigningKey != "" {
		t.Fatalf("expected empty approval signing key from env, got %q", cfg.ApprovalSigningKey)
	}

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when APPROVAL_SIGNING_KEY is missing")
	}
	if !strings.Contains(err.Error(), "approval_signing_key must be set") {
		t.Fatalf("expected missing approval signing key error, got: %v", err)
	}
}

func TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", testutil.ToolRegistryConfigPath())
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	if cfg.ApprovalSigningKey == "" {
		t.Fatal("expected APPROVAL_SIGNING_KEY to be loaded from env")
	}

	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("expected strict startup success with strong APPROVAL_SIGNING_KEY: %v", err)
	}
	defer func() {
		_ = gw.Close()
	}()
}
