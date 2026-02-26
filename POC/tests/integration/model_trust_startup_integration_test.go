package integration

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/gateway"
	"github.com/RamXX/agentic_reference_architecture/POC/internal/testutil"
)

func TestGatewayStartupFailsWithUnsignedModelProviderCatalogWhenKeyConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations config: %v", err)
	}
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

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPath := filepath.Join(tmpDir, "catalog.pub")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	cfg := &gateway.Config{
		Port:                          0,
		UpstreamURL:                   "http://localhost:8080",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "dev",
		DestinationsConfigPath:        destinationsPath,
		RateLimitRPM:                  100000,
		RateLimitBurst:                100000,
		ModelProviderCatalogPath:      catalogPath,
		ModelProviderCatalogPublicKey: pubPath,
	}

	_, err = gateway.New(cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("expected startup failure due unsigned catalog/signature verification, got: %v", err)
	}
}

func TestGatewayStartupFailsClosedOnGuardArtifactDigestMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	destinationsPath := filepath.Join(tmpDir, "destinations.yaml")
	if err := os.WriteFile(destinationsPath, []byte("allowed_destinations:\n  - \"127.0.0.1\"\n  - \"localhost\"\n  - \"::1\"\n"), 0644); err != nil {
		t.Fatalf("write destinations config: %v", err)
	}
	artifactPath := filepath.Join(tmpDir, "guard-model.bin")
	if err := os.WriteFile(artifactPath, []byte("guard-model-binary"), 0644); err != nil {
		t.Fatalf("write guard artifact: %v", err)
	}

	// Use the project's real attestation key so tool registry and catalog
	// signature checks pass. We only want the guard artifact *digest* to fail.
	projectPubKey := filepath.Join(testutil.ProjectRoot(), "config", "attestation-ed25519.pub")

	// Use the project's real signed model provider catalog so catalog
	// signature verification passes and we reach the guard artifact check.
	catalogPath := filepath.Join(testutil.ProjectRoot(), "config", "model-provider-catalog.v2.yaml")

	// Strict profile (prod_standard) requires all security fields to be set.
	// Supply everything except a correct guard artifact digest so the digest
	// mismatch is the specific failure we hit.
	cfg := &gateway.Config{
		Port:                          0,
		UpstreamURL:                   "https://localhost:8080",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		ToolRegistryConfigPath:        testutil.ToolRegistryConfigPath(),
		ToolRegistryPublicKey:         projectPubKey,
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "prod",
		DestinationsConfigPath:        destinationsPath,
		RateLimitRPM:                  100000,
		RateLimitBurst:                100000,
		EnforcementProfile:            "prod_standard",
		ApprovalSigningKey:            "this-is-a-strong-signing-key-for-test-purposes-only-32chars",
		ModelProviderCatalogPath:      catalogPath,
		ModelProviderCatalogPublicKey: projectPubKey,
		GuardArtifactPath:             artifactPath,
		GuardArtifactSHA256:           "deadbeef",
		GuardArtifactPublicKey:        projectPubKey,
	}

	_, err := gateway.New(cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest mismatch") {
		t.Fatalf("expected fail-closed startup error for guard artifact mismatch, got: %v", err)
	}
}
