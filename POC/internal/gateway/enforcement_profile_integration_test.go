package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func setStrictAttestationFixtureEnv(t *testing.T) {
	t.Helper()

	projectRoot := testutil.ProjectRoot()
	attestationPubKey := filepath.Join(projectRoot, "config", "attestation-ed25519.pub")
	toolRegistryPath := filepath.Join(projectRoot, "config", "tool-registry.yaml")
	modelCatalogPath := filepath.Join(projectRoot, "config", "model-provider-catalog.v2.yaml")
	guardArtifactPath := filepath.Join(projectRoot, "config", "guard-artifact.bin")

	guardBytes, err := os.ReadFile(guardArtifactPath)
	if err != nil {
		t.Fatalf("read guard artifact fixture: %v", err)
	}
	guardSum := sha256.Sum256(guardBytes)
	guardDigest := hex.EncodeToString(guardSum[:])

	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", toolRegistryPath)
	t.Setenv("TOOL_REGISTRY_PUBLIC_KEY", attestationPubKey)
	t.Setenv("MODEL_PROVIDER_CATALOG_PATH", modelCatalogPath)
	t.Setenv("MODEL_PROVIDER_CATALOG_PUBLIC_KEY", attestationPubKey)
	t.Setenv("GUARD_ARTIFACT_PATH", guardArtifactPath)
	t.Setenv("GUARD_ARTIFACT_SHA256", guardDigest)
	t.Setenv("GUARD_ARTIFACT_SIGNATURE_PATH", guardArtifactPath+".sig")
	t.Setenv("GUARD_ARTIFACT_PUBLIC_KEY", attestationPubKey)
}

func TestEnforcementProfile_StrictStartupFailsFastWithoutApprovalSigningKey(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
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
	setStrictAttestationFixtureEnv(t)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
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

func TestEnforcementProfile_StrictStartupFailsWithUnsignedToolRegistry(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	projectRoot := testutil.ProjectRoot()
	sourceRegistry := filepath.Join(projectRoot, "config", "tool-registry.yaml")
	registryBytes, err := os.ReadFile(sourceRegistry)
	if err != nil {
		t.Fatalf("read source tool registry: %v", err)
	}
	tmpRegistryPath := filepath.Join(t.TempDir(), "tool-registry.yaml")
	if err := os.WriteFile(tmpRegistryPath, registryBytes, 0644); err != nil {
		t.Fatalf("write temporary tool registry: %v", err)
	}

	t.Setenv("UPSTREAM_URL", upstream.URL)
	t.Setenv("OPA_POLICY_DIR", testutil.OPAPolicyDir())
	t.Setenv("OPA_POLICY_PATH", testutil.OPAPolicyPath())
	setStrictAttestationFixtureEnv(t)
	t.Setenv("TOOL_REGISTRY_CONFIG_PATH", tmpRegistryPath)
	t.Setenv("AUDIT_LOG_PATH", filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv("ENFORCEMENT_PROFILE", enforcementProfileProdStandard)
	t.Setenv("SPIFFE_MODE", "prod")
	t.Setenv("KEYDB_URL", "redis://keydb:6379")
	t.Setenv("MCP_TRANSPORT_MODE", "mcp")
	t.Setenv("ENFORCE_MODEL_MEDIATION_GATE", "true")
	t.Setenv("ENFORCE_HIPAA_PROMPT_SAFETY_GATE", "true")
	t.Setenv("APPROVAL_SIGNING_KEY", "prod-approval-signing-key-material-at-least-32")

	cfg := ConfigFromEnv()
	_, err = New(cfg)
	if err == nil {
		t.Fatal("expected strict startup failure when tool registry signature is missing")
	}
	if !strings.Contains(err.Error(), "strict tool registry attestation verification failed") {
		t.Fatalf("expected strict registry attestation failure, got: %v", err)
	}
}
