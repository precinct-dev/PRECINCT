// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway"
	"github.com/precinct-dev/precinct/internal/testutil"
)

func writeSignedStrictToolRegistryFixture(t *testing.T) (configPath, publicKeyPath string) {
	t.Helper()

	sourceRegistry := filepath.Join(testutil.ProjectRoot(), "config", "tool-registry.yaml")
	registryBytes, err := os.ReadFile(sourceRegistry)
	if err != nil {
		t.Fatalf("read source tool registry: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate attestation key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal attestation public key: %v", err)
	}

	fixtureDir := t.TempDir()
	configPath = filepath.Join(fixtureDir, "tool-registry.yaml")
	if err := os.WriteFile(configPath, registryBytes, 0o644); err != nil {
		t.Fatalf("write signed registry fixture: %v", err)
	}
	sig := ed25519.Sign(priv, registryBytes)
	if err := os.WriteFile(configPath+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		t.Fatalf("write registry signature: %v", err)
	}

	publicKeyPath = filepath.Join(fixtureDir, "attestation-ed25519.pub")
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil {
		t.Fatalf("write attestation public key: %v", err)
	}

	return configPath, publicKeyPath
}

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
		RiskThresholdsPath:            filepath.Join(testutil.ProjectRoot(), "config", "risk_thresholds.yaml"),
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
	toolRegistryPath, toolRegistryPubKey := writeSignedStrictToolRegistryFixture(t)

	// Strict profile (prod_standard) requires all security fields to be set.
	// Supply everything except a correct guard artifact digest so the digest
	// mismatch is the specific failure we hit.
	cfg := &gateway.Config{
		Port:                          0,
		UpstreamURL:                   "https://localhost:8080",
		OPAPolicyDir:                  testutil.OPAPolicyDir(),
		OPAPolicyPublicKey:            toolRegistryPubKey,
		ToolRegistryConfigPath:        toolRegistryPath,
		ToolRegistryPublicKey:         toolRegistryPubKey,
		AuditLogPath:                  "",
		OPAPolicyPath:                 testutil.OPAPolicyPath(),
		MaxRequestSizeBytes:           1024 * 1024,
		SPIFFEMode:                    "prod",
		AdminAuthzAllowedSPIFFEIDs:    []string{"spiffe://poc.local/admin/security"},
		DestinationsConfigPath:        destinationsPath,
		RiskThresholdsPath:            filepath.Join(testutil.ProjectRoot(), "config", "risk_thresholds.yaml"),
		RateLimitRPM:                  100000,
		RateLimitBurst:                100000,
		EnforcementProfile:            "prod_standard",
		ApprovalSigningKey:            "this-is-a-strong-signing-key-for-test-purposes-only-32chars",
		KeyDBURL:                      "redis://keydb:6379",
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
