package gateway

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/PRECINCT/POC/internal/gateway/middleware"
	"github.com/precinct-dev/PRECINCT/POC/internal/testutil"
)

func TestModelProviderCatalogSignatureVerification(t *testing.T) {
	tmpDir := t.TempDir()
	catalogPath := filepath.Join(tmpDir, "catalog.yaml")
	catalog := []byte(`version: "v2"
providers:
  - name: "groq"
    endpoint: "https://api.groq.com/openai/v1/chat/completions"
    allowed_models: ["llama-3.3-70b-versatile"]
    allowed_residency: ["us"]
    allow_high_risk_mode: false
    fallback_providers: ["openai"]
`)
	if err := os.WriteFile(catalogPath, catalog, 0644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath := filepath.Join(tmpDir, "catalog.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	engine := newModelPlanePolicyEngine()
	if err := engine.loadProviderCatalog(catalogPath, pubPath); err == nil {
		t.Fatal("expected catalog load to fail without signature file")
	}

	sig := ed25519.Sign(priv, catalog)
	if err := os.WriteFile(catalogPath+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	if err := engine.loadProviderCatalog(catalogPath, pubPath); err != nil {
		t.Fatalf("expected signed catalog to load, got error: %v", err)
	}
	meta := engine.catalogMetadata()
	if verified, _ := meta["provider_catalog_signature_verified"].(bool); !verified {
		t.Fatalf("expected signature_verified=true metadata=%v", meta)
	}
	if version, _ := meta["provider_catalog_version"].(string); version != "v2" {
		t.Fatalf("expected catalog version v2, got %q", version)
	}
}

func TestModelProviderEndpointDriftDetection(t *testing.T) {
	tmpDir := t.TempDir()
	catalogPath := filepath.Join(tmpDir, "catalog.yaml")
	catalog := []byte(`version: "v2"
providers:
  - name: "groq"
    endpoint: "https://api.groq.com/openai/v1/chat/completions"
    allowed_models: ["llama-3.3-70b-versatile"]
    allowed_residency: ["us"]
    allow_high_risk_mode: false
    fallback_providers: []
`)
	if err := os.WriteFile(catalogPath, catalog, 0644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	engine := newModelPlanePolicyEngine()
	if err := engine.loadProviderCatalog(catalogPath, ""); err != nil {
		t.Fatalf("load unsigned catalog in dev mode: %v", err)
	}

	g := &Gateway{
		modelPlanePolicy:     engine,
		destinationAllowlist: middleware.DefaultDestinationAllowlist(),
	}
	_, err := g.resolveProviderTarget("groq", map[string]any{
		"provider_endpoint_groq": "https://evil.example.com/openai/v1/chat/completions",
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "drift") {
		t.Fatalf("expected drift detection error, got: %v", err)
	}
}

func TestGuardArtifactIntegrityFailClosedOutsideDev(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "guard.bin")
	if err := os.WriteFile(artifactPath, []byte("guard-model"), 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	cfg := &Config{
		GuardArtifactPath:   artifactPath,
		GuardArtifactSHA256: "deadbeef",
	}
	if err := verifyGuardArtifactIntegrity(cfg, enforcementProfileProdStandard, nil); err == nil {
		t.Fatal("expected digest mismatch to fail closed for prod_standard profile")
	}

	if err := verifyGuardArtifactIntegrity(cfg, enforcementProfileDev, nil); err != nil {
		t.Fatalf("expected digest mismatch to warn-only in dev, got error: %v", err)
	}
}

func TestGuardArtifactIntegrityStrictFailureEmitsAuditEvent(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "guard.bin")
	if err := os.WriteFile(artifactPath, []byte("guard-model"), 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	auditor, err := middleware.NewAuditor(auditPath, testutil.OPAPolicyPath(), testutil.ToolRegistryConfigPath())
	if err != nil {
		t.Fatalf("create auditor: %v", err)
	}
	defer func() {
		_ = auditor.Close()
	}()

	cfg := &Config{
		GuardArtifactPath:   artifactPath,
		GuardArtifactSHA256: "deadbeef",
	}
	err = verifyGuardArtifactIntegrity(cfg, enforcementProfileProdStandard, auditor)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest mismatch") {
		t.Fatalf("expected strict digest mismatch error, got: %v", err)
	}

	auditor.Flush()
	content, readErr := os.ReadFile(auditPath)
	if readErr != nil {
		t.Fatalf("read audit log: %v", readErr)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one audit event")
	}
	var event map[string]any
	if unmarshalErr := json.Unmarshal([]byte(lines[len(lines)-1]), &event); unmarshalErr != nil {
		t.Fatalf("decode audit event: %v", unmarshalErr)
	}
	if action, _ := event["action"].(string); action != "model.guard_artifact.verify" {
		t.Fatalf("expected action model.guard_artifact.verify, got %q", action)
	}
	result, _ := event["result"].(string)
	if !strings.Contains(result, "status=fail") || !strings.Contains(result, "detail=digest_mismatch") {
		t.Fatalf("expected fail digest_mismatch audit result, got %q", result)
	}
}
