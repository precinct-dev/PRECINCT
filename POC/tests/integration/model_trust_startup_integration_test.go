package integration

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/example/agentic-security-poc/internal/gateway"
	"github.com/example/agentic-security-poc/internal/testutil"
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

	cfg := &gateway.Config{
		Port:                   0,
		UpstreamURL:            "http://localhost:8080",
		OPAPolicyDir:           testutil.OPAPolicyDir(),
		ToolRegistryConfigPath: testutil.ToolRegistryConfigPath(),
		AuditLogPath:           "",
		OPAPolicyPath:          testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:    1024 * 1024,
		SPIFFEMode:             "prod",
		DestinationsConfigPath: destinationsPath,
		RateLimitRPM:           100000,
		RateLimitBurst:         100000,
		EnforcementProfile:     "prod_standard",
		GuardArtifactPath:      artifactPath,
		GuardArtifactSHA256:    "deadbeef",
	}

	_, err := gateway.New(cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "digest mismatch") {
		t.Fatalf("expected fail-closed startup error for guard artifact mismatch, got: %v", err)
	}
}
