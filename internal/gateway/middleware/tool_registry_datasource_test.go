// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// OC-cqj0: Tests for DataSourceDefinition struct, registry extension, YAML parsing,
// GetDataSource lookup, ComputeDataSourceHash, and hot-reload with data sources.
package middleware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDataSourceDefinition_YAMLParsing verifies that data_sources are loaded from YAML config.
func TestDataSourceDefinition_YAMLParsing(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
ui_resources: []
data_sources:
  - uri: "https://gist.github.com/owner/abc123/raw"
    content_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    approved_at: "2026-03-01T00:00:00Z"
    approved_by: "spiffe://poc.local/admin/security"
    max_size_bytes: 1048576
    mutable_policy: "block_on_change"
    refresh_ttl: 1h
  - uri: "https://config.internal.example.com/policies.json"
    content_hash: "sha256:a948904f2f0f479b8f8564e9e89dfdd84b6b0e57f32ead2bda6c507b0fc98933"
    approved_at: "2026-02-15T08:30:00Z"
    approved_by: "spiffe://poc.local/admin/ops"
    max_size_bytes: 524288
    mutable_policy: "flag_on_change"
    refresh_ttl: 30m
    last_verified: "2026-03-01T12:00:00Z"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Verify count
	if registry.DataSourceCount() != 2 {
		t.Fatalf("Expected 2 data sources, got %d", registry.DataSourceCount())
	}

	// Verify first data source fields
	ds1, exists := registry.GetDataSource("https://gist.github.com/owner/abc123/raw")
	if !exists {
		t.Fatal("Expected gist data source to exist")
	}
	if ds1.URI != "https://gist.github.com/owner/abc123/raw" {
		t.Errorf("Expected URI https://gist.github.com/owner/abc123/raw, got %s", ds1.URI)
	}
	if ds1.ContentHash != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Unexpected ContentHash: %s", ds1.ContentHash)
	}
	expectedTime, _ := time.Parse(time.RFC3339, "2026-03-01T00:00:00Z")
	if !ds1.ApprovedAt.Equal(expectedTime) {
		t.Errorf("Expected ApprovedAt %v, got %v", expectedTime, ds1.ApprovedAt)
	}
	if ds1.ApprovedBy != "spiffe://poc.local/admin/security" {
		t.Errorf("Expected ApprovedBy spiffe://poc.local/admin/security, got %s", ds1.ApprovedBy)
	}
	if ds1.MaxSizeBytes != 1048576 {
		t.Errorf("Expected MaxSizeBytes 1048576, got %d", ds1.MaxSizeBytes)
	}
	if ds1.MutablePolicy != "block_on_change" {
		t.Errorf("Expected MutablePolicy block_on_change, got %s", ds1.MutablePolicy)
	}
	if ds1.RefreshTTL != time.Hour {
		t.Errorf("Expected RefreshTTL 1h, got %v", ds1.RefreshTTL)
	}
	if !ds1.LastVerified.IsZero() {
		t.Errorf("Expected LastVerified to be zero, got %v", ds1.LastVerified)
	}

	// Verify second data source
	ds2, exists := registry.GetDataSource("https://config.internal.example.com/policies.json")
	if !exists {
		t.Fatal("Expected config data source to exist")
	}
	if ds2.MutablePolicy != "flag_on_change" {
		t.Errorf("Expected MutablePolicy flag_on_change, got %s", ds2.MutablePolicy)
	}
	if ds2.RefreshTTL != 30*time.Minute {
		t.Errorf("Expected RefreshTTL 30m, got %v", ds2.RefreshTTL)
	}
	expectedVerified, _ := time.Parse(time.RFC3339, "2026-03-01T12:00:00Z")
	if !ds2.LastVerified.Equal(expectedVerified) {
		t.Errorf("Expected LastVerified %v, got %v", expectedVerified, ds2.LastVerified)
	}
}

// TestDataSourceDefinition_EmptySection verifies registry loads with empty data_sources.
func TestDataSourceDefinition_EmptySection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools:
  - name: "test_tool"
    description: "A test tool"
    hash: "abc123"
    risk_level: "low"
data_sources: []
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if registry.DataSourceCount() != 0 {
		t.Errorf("Expected 0 data sources, got %d", registry.DataSourceCount())
	}
	if registry.ToolCount() != 1 {
		t.Errorf("Expected 1 tool, got %d", registry.ToolCount())
	}
}

// TestDataSourceDefinition_OmittedSection verifies registry loads when data_sources is absent.
func TestDataSourceDefinition_OmittedSection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools:
  - name: "test_tool"
    description: "A test tool"
    hash: "abc123"
    risk_level: "low"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if registry.DataSourceCount() != 0 {
		t.Errorf("Expected 0 data sources when section omitted, got %d", registry.DataSourceCount())
	}
}

// TestGetDataSource_Found verifies GetDataSource returns the definition for a known URI.
func TestGetDataSource_Found(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
data_sources:
  - uri: "https://example.com/data.json"
    content_hash: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    approved_by: "spiffe://poc.local/admin"
    mutable_policy: "block_on_change"
    refresh_ttl: 5m
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	ds, exists := registry.GetDataSource("https://example.com/data.json")
	if !exists {
		t.Fatal("Expected data source to exist")
	}
	if ds.URI != "https://example.com/data.json" {
		t.Errorf("Expected URI https://example.com/data.json, got %s", ds.URI)
	}
	if ds.MutablePolicy != "block_on_change" {
		t.Errorf("Expected MutablePolicy block_on_change, got %s", ds.MutablePolicy)
	}
}

// TestGetDataSource_NotFound verifies GetDataSource returns false for unknown URI.
func TestGetDataSource_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
data_sources:
  - uri: "https://example.com/data.json"
    content_hash: "sha256:abcdef1234567890"
    mutable_policy: "block_on_change"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	ds, exists := registry.GetDataSource("https://unknown.example.com/no-such-file")
	if exists {
		t.Error("Expected data source to NOT exist for unknown URI")
	}
	if ds != nil {
		t.Error("Expected nil pointer for not-found data source")
	}
}

// TestComputeDataSourceHash verifies SHA-256 hash computation with "sha256:" prefix.
func TestComputeDataSourceHash(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    string
	}{
		{
			name:    "EmptyContent",
			content: []byte(""),
			want:    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:    "HelloWorld",
			content: []byte("Hello, World!"),
			want:    "sha256:" + computeExpectedSHA256("Hello, World!"),
		},
		{
			name:    "BinaryContent",
			content: []byte{0x00, 0x01, 0x02, 0xff},
			want:    "sha256:" + computeExpectedSHA256Bytes([]byte{0x00, 0x01, 0x02, 0xff}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeDataSourceHash(tt.content)
			if got != tt.want {
				t.Errorf("ComputeDataSourceHash() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestComputeDataSourceHash_Deterministic verifies hash is deterministic.
func TestComputeDataSourceHash_Deterministic(t *testing.T) {
	content := []byte("deterministic content check")
	hash1 := ComputeDataSourceHash(content)
	hash2 := ComputeDataSourceHash(content)
	if hash1 != hash2 {
		t.Errorf("ComputeDataSourceHash should be deterministic: %s != %s", hash1, hash2)
	}
}

// TestComputeDataSourceHash_PrefixFormat verifies the "sha256:" prefix format.
func TestComputeDataSourceHash_PrefixFormat(t *testing.T) {
	hash := ComputeDataSourceHash([]byte("test"))
	if !strings.HasPrefix(hash, "sha256:") {
		t.Errorf("Expected hash to have sha256: prefix, got %s", hash)
	}
	// "sha256:" (7 chars) + 64 hex chars = 71 chars total
	if len(hash) != 71 {
		t.Errorf("Expected hash length 71 (prefix + 64 hex), got %d", len(hash))
	}
}

// TestComputeDataSourceHash_DifferentInputs verifies different content produces different hashes.
func TestComputeDataSourceHash_DifferentInputs(t *testing.T) {
	hash1 := ComputeDataSourceHash([]byte("content A"))
	hash2 := ComputeDataSourceHash([]byte("content B"))
	if hash1 == hash2 {
		t.Error("Different content should produce different hashes")
	}
}

// TestWatch_DataSourcesReloadedOnFileChange verifies hot-reload updates data sources.
func TestWatch_DataSourcesReloadedOnFileChange(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	initialConfig := `tools:
  - name: "tool_one"
    description: "Tool one"
    hash: "hash_one"
    risk_level: "low"
data_sources: []
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if registry.DataSourceCount() != 0 {
		t.Fatalf("Expected 0 data sources initially, got %d", registry.DataSourceCount())
	}

	stop, err := registry.Watch()
	if err != nil {
		t.Fatalf("Watch() returned error: %v", err)
	}
	defer stop()

	updatedConfig := `tools:
  - name: "tool_one"
    description: "Tool one"
    hash: "hash_one"
    risk_level: "low"
data_sources:
  - uri: "https://example.com/new-data.json"
    content_hash: "sha256:aabbccdd"
    approved_by: "spiffe://poc.local/admin/security"
    mutable_policy: "block_on_change"
    refresh_ttl: 15m
  - uri: "https://example.com/second.json"
    content_hash: "sha256:11223344"
    mutable_policy: "allow"
    refresh_ttl: 1h
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for reload with polling
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if registry.DataSourceCount() == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if registry.DataSourceCount() != 2 {
		t.Fatalf("Expected 2 data sources after reload, got %d", registry.DataSourceCount())
	}

	ds, exists := registry.GetDataSource("https://example.com/new-data.json")
	if !exists {
		t.Fatal("Expected new-data.json data source to exist after reload")
	}
	if ds.ContentHash != "sha256:aabbccdd" {
		t.Errorf("Expected content_hash sha256:aabbccdd, got %s", ds.ContentHash)
	}
	if ds.MutablePolicy != "block_on_change" {
		t.Errorf("Expected mutable_policy block_on_change, got %s", ds.MutablePolicy)
	}

	ds2, exists := registry.GetDataSource("https://example.com/second.json")
	if !exists {
		t.Fatal("Expected second.json data source to exist after reload")
	}
	if ds2.MutablePolicy != "allow" {
		t.Errorf("Expected mutable_policy allow, got %s", ds2.MutablePolicy)
	}
}

// TestWatch_DataSourceRemovalAfterReload verifies atomic swap removes old data sources.
func TestWatch_DataSourceRemovalAfterReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	initialConfig := `tools: []
data_sources:
  - uri: "https://example.com/will-be-removed.json"
    content_hash: "sha256:remove_me"
    mutable_policy: "block_on_change"
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if registry.DataSourceCount() != 1 {
		t.Fatalf("Expected 1 data source initially, got %d", registry.DataSourceCount())
	}

	stop, err := registry.Watch()
	if err != nil {
		t.Fatalf("Watch() returned error: %v", err)
	}
	defer stop()

	// Update with no data sources
	updatedConfig := `tools: []
data_sources: []
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if registry.DataSourceCount() == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if registry.DataSourceCount() != 0 {
		t.Fatalf("Expected 0 data sources after reload, got %d", registry.DataSourceCount())
	}

	_, exists := registry.GetDataSource("https://example.com/will-be-removed.json")
	if exists {
		t.Error("Expected removed data source to no longer exist after reload")
	}
}

// TestWatch_ConcurrentDataSourceReadsDuringReload verifies concurrent-safe reads.
func TestWatch_ConcurrentDataSourceReadsDuringReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
data_sources:
  - uri: "https://example.com/concurrent.json"
    content_hash: "sha256:concurrent_hash"
    mutable_policy: "block_on_change"
    refresh_ttl: 10m
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	stop, err := registry.Watch()
	if err != nil {
		t.Fatalf("Watch() returned error: %v", err)
	}
	defer stop()

	// Concurrent readers while config is being rewritten
	var wg sync.WaitGroup
	errors := make(chan string, 100)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// These should never panic even during reload
				_ = registry.DataSourceCount()
				ds, exists := registry.GetDataSource("https://example.com/concurrent.json")
				if exists && ds.ContentHash == "" {
					errors <- "got empty ContentHash from concurrent read"
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Trigger reload in the middle
	updatedConfig := `tools: []
data_sources:
  - uri: "https://example.com/concurrent.json"
    content_hash: "sha256:updated_hash"
    mutable_policy: "flag_on_change"
    refresh_ttl: 20m
`
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	wg.Wait()
	close(errors)

	for errMsg := range errors {
		t.Error(errMsg)
	}
}

// TestReload_IncludesDataSources verifies explicit Reload() includes data sources.
func TestReload_IncludesDataSources(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools:
  - name: "tool_a"
    description: "Tool A"
    hash: "hash_a"
    risk_level: "low"
data_sources:
  - uri: "https://example.com/ds1.json"
    content_hash: "sha256:ds1hash"
    mutable_policy: "block_on_change"
  - uri: "https://example.com/ds2.json"
    content_hash: "sha256:ds2hash"
    mutable_policy: "flag_on_change"
  - uri: "https://example.com/ds3.json"
    content_hash: "sha256:ds3hash"
    mutable_policy: "allow"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	result, err := registry.Reload()
	if err != nil {
		t.Fatalf("Reload() failed: %v", err)
	}

	if result.ToolCount != 1 {
		t.Errorf("Expected ToolCount 1, got %d", result.ToolCount)
	}
	if result.DataSourceCount != 3 {
		t.Errorf("Expected DataSourceCount 3, got %d", result.DataSourceCount)
	}
}

// TestWatch_DataSourcesProtectedByAttestation verifies Ed25519 signature verification
// applies to registry file updates that include data_sources.
func TestWatch_DataSourcesProtectedByAttestation(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	// Generate Ed25519 keypair for attestation
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	initialConfig := `tools:
  - name: "attested_tool"
    description: "Attested tool"
    hash: "attested_hash"
    risk_level: "low"
data_sources:
  - uri: "https://example.com/attested-ds.json"
    content_hash: "sha256:attested_ds_hash"
    mutable_policy: "block_on_change"
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Set the public key for attestation
	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixPub})
	if err := registry.SetPublicKey(pemBlock); err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	stop, watchErr := registry.Watch()
	if watchErr != nil {
		t.Fatalf("Watch() returned error: %v", watchErr)
	}
	defer stop()

	// Write updated config with a new data source and valid signature
	updatedConfig := `tools:
  - name: "attested_tool"
    description: "Attested tool"
    hash: "attested_hash"
    risk_level: "low"
data_sources:
  - uri: "https://example.com/attested-ds.json"
    content_hash: "sha256:attested_ds_hash"
    mutable_policy: "block_on_change"
  - uri: "https://example.com/new-attested-ds.json"
    content_hash: "sha256:new_attested_hash"
    mutable_policy: "flag_on_change"
    refresh_ttl: 2h
`
	sig := ed25519.Sign(priv, []byte(updatedConfig))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	sigPath := configPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sigB64), 0644); err != nil {
		t.Fatalf("Failed to write sig: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("Failed to write updated config: %v", err)
	}

	// Wait for reload
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if registry.DataSourceCount() == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if registry.DataSourceCount() != 2 {
		t.Fatalf("Expected 2 data sources after signed reload, got %d", registry.DataSourceCount())
	}

	ds, exists := registry.GetDataSource("https://example.com/new-attested-ds.json")
	if !exists {
		t.Fatal("Expected new-attested-ds.json to exist after signed reload")
	}
	if ds.ContentHash != "sha256:new_attested_hash" {
		t.Errorf("Expected content_hash sha256:new_attested_hash, got %s", ds.ContentHash)
	}
}

// TestWatch_DataSourcesRejectedOnBadSignature verifies that unsigned updates to data_sources
// are rejected when attestation is enabled, preserving the old registry.
func TestWatch_DataSourcesRejectedOnBadSignature(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	initialConfig := `tools: []
data_sources:
  - uri: "https://example.com/protected.json"
    content_hash: "sha256:original_hash"
    mutable_policy: "block_on_change"
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to write initial config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixPub})
	if err := registry.SetPublicKey(pemBlock); err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	stop, watchErr := registry.Watch()
	if watchErr != nil {
		t.Fatalf("Watch() returned error: %v", watchErr)
	}
	defer stop()

	// Write updated config WITHOUT a valid signature -- should be rejected
	attackerConfig := `tools: []
data_sources:
  - uri: "https://example.com/protected.json"
    content_hash: "sha256:attacker_modified_hash"
    mutable_policy: "allow"
  - uri: "https://evil.com/malicious.json"
    content_hash: "sha256:evil_hash"
    mutable_policy: "allow"
`
	// Write bad sig
	if err := os.WriteFile(configPath+".sig", []byte("badsignature"), 0644); err != nil {
		t.Fatalf("Failed to write bad sig: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(attackerConfig), 0644); err != nil {
		t.Fatalf("Failed to write attacker config: %v", err)
	}

	// Wait and verify old registry is preserved
	time.Sleep(500 * time.Millisecond)

	if registry.DataSourceCount() != 1 {
		t.Fatalf("Expected 1 data source (old preserved), got %d", registry.DataSourceCount())
	}

	ds, exists := registry.GetDataSource("https://example.com/protected.json")
	if !exists {
		t.Fatal("Expected original data source to still exist")
	}
	if ds.ContentHash != "sha256:original_hash" {
		t.Errorf("Expected original hash preserved, got %s", ds.ContentHash)
	}

	_, evilExists := registry.GetDataSource("https://evil.com/malicious.json")
	if evilExists {
		t.Error("Evil data source should NOT exist after rejected unsigned reload")
	}
}

// TestDataSourceCoexistsWithToolsAndUIResources verifies all three registry
// sections (tools, ui_resources, data_sources) coexist in a single YAML file.
func TestDataSourceCoexistsWithToolsAndUIResources(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	htmlContent := []byte("<html>Dashboard</html>")
	contentHash := computeTestHash(htmlContent)

	config := `tools:
  - name: "search"
    description: "Search tool"
    hash: "search_hash"
    risk_level: "low"
ui_resources:
  - server: "dashboard-server"
    resource_uri: "ui://dashboard/main.html"
    content_hash: "` + contentHash + `"
    version: "1.0.0"
    max_size_bytes: 524288
data_sources:
  - uri: "https://example.com/data.json"
    content_hash: "sha256:data_hash"
    mutable_policy: "block_on_change"
    refresh_ttl: 30m
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if registry.ToolCount() != 1 {
		t.Errorf("Expected 1 tool, got %d", registry.ToolCount())
	}
	if registry.UIResourceCount() != 1 {
		t.Errorf("Expected 1 UI resource, got %d", registry.UIResourceCount())
	}
	if registry.DataSourceCount() != 1 {
		t.Errorf("Expected 1 data source, got %d", registry.DataSourceCount())
	}

	// Verify each section is independent
	_, toolExists := registry.GetToolDefinition("search")
	if !toolExists {
		t.Error("Expected search tool to exist")
	}

	_, uiExists := registry.GetUIResource("dashboard-server", "ui://dashboard/main.html")
	if !uiExists {
		t.Error("Expected UI resource to exist")
	}

	ds, dsExists := registry.GetDataSource("https://example.com/data.json")
	if !dsExists {
		t.Fatal("Expected data source to exist")
	}
	if ds.RefreshTTL != 30*time.Minute {
		t.Errorf("Expected RefreshTTL 30m, got %v", ds.RefreshTTL)
	}
}

// TestGetDataSource_ReturnsPointerCopy verifies GetDataSource returns a pointer
// that does not alias the internal map entry (mutation safety).
func TestGetDataSource_ReturnsPointerCopy(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
data_sources:
  - uri: "https://example.com/immutable-test.json"
    content_hash: "sha256:immutable_hash"
    mutable_policy: "block_on_change"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	ds1, exists := registry.GetDataSource("https://example.com/immutable-test.json")
	if !exists {
		t.Fatal("Expected data source to exist")
	}

	// Mutate the returned pointer -- should NOT affect the internal map
	ds1.ContentHash = "sha256:MUTATED"

	ds2, _ := registry.GetDataSource("https://example.com/immutable-test.json")
	if ds2.ContentHash == "sha256:MUTATED" {
		t.Error("Mutation of returned pointer should NOT affect internal registry state")
	}
	if ds2.ContentHash != "sha256:immutable_hash" {
		t.Errorf("Expected original hash sha256:immutable_hash, got %s", ds2.ContentHash)
	}
}

// TestDataSourceDuplicateURIs verifies that duplicate URIs in YAML use last-wins.
func TestDataSourceDuplicateURIs(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "tool-registry.yaml")

	config := `tools: []
data_sources:
  - uri: "https://example.com/dup.json"
    content_hash: "sha256:first_hash"
    mutable_policy: "block_on_change"
  - uri: "https://example.com/dup.json"
    content_hash: "sha256:second_hash"
    mutable_policy: "flag_on_change"
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	registry, err := NewToolRegistry(configPath)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Last entry wins (iteration order in the YAML list)
	if registry.DataSourceCount() != 1 {
		t.Errorf("Expected 1 data source (deduped by URI), got %d", registry.DataSourceCount())
	}
	ds, exists := registry.GetDataSource("https://example.com/dup.json")
	if !exists {
		t.Fatal("Expected data source to exist")
	}
	if ds.ContentHash != "sha256:second_hash" {
		t.Errorf("Expected last-wins hash sha256:second_hash, got %s", ds.ContentHash)
	}
	if ds.MutablePolicy != "flag_on_change" {
		t.Errorf("Expected last-wins policy flag_on_change, got %s", ds.MutablePolicy)
	}
}

// --- Test helpers ---

// computeExpectedSHA256 computes the raw hex SHA-256 for a string (no prefix).
func computeExpectedSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// computeExpectedSHA256Bytes computes the raw hex SHA-256 for bytes (no prefix).
func computeExpectedSHA256Bytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
