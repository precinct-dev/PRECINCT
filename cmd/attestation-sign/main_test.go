// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestSignArtifact_ProducesValidSignature verifies that signArtifact produces
// a base64-encoded Ed25519 signature that can be verified with the
// corresponding public key -- the same algorithm used by verifyBlobSignature
// in the gateway.
func TestSignArtifact_ProducesValidSignature(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a temp keypair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Write a test artifact
	payload := []byte("test artifact content for signing verification")
	artifactPath := filepath.Join(tmpDir, "test-artifact.bin")
	if err := os.WriteFile(artifactPath, payload, 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	// Sign it
	if err := signArtifact(artifactPath, priv); err != nil {
		t.Fatalf("signArtifact: %v", err)
	}

	// Read the .sig file
	sigData, err := os.ReadFile(artifactPath + ".sig")
	if err != nil {
		t.Fatalf("read sig file: %v", err)
	}

	// Decode base64
	sig, err := base64.StdEncoding.DecodeString(string(sigData))
	if err != nil {
		t.Fatalf("decode base64 signature: %v", err)
	}

	// Verify with ed25519.Verify (same as gateway's verifyBlobSignature)
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("signature verification failed: signArtifact produced an invalid signature")
	}
}

// TestSignArtifact_FailsOnMissingFile verifies error handling for missing files.
func TestSignArtifact_FailsOnMissingFile(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	err := signArtifact("/nonexistent/path/artifact.bin", priv)
	if err == nil {
		t.Fatal("expected error for missing artifact file")
	}
}

// TestParsePrivateKeyPEM_ValidKey verifies PEM PKCS8 Ed25519 private key parsing.
func TestParsePrivateKeyPEM_ValidKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	parsed, err := parsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM: %v", err)
	}

	if !parsed.Equal(priv) {
		t.Fatal("parsed key does not match original")
	}
}

// TestParsePrivateKeyPEM_InvalidPEM verifies error on garbage input.
func TestParsePrivateKeyPEM_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKeyPEM([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// TestLoadOrGenerateKeypair_GeneratesWhenMissing verifies keypair generation.
func TestLoadOrGenerateKeypair_GeneratesWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}
	// Place a go.mod so findProjectRoot-like logic would work, but we
	// call loadOrGenerateKeypair directly with tmpDir as project root.

	priv, generated, err := loadOrGenerateKeypair(tmpDir)
	if err != nil {
		t.Fatalf("loadOrGenerateKeypair: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true when no key exists")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected %d byte private key, got %d", ed25519.PrivateKeySize, len(priv))
	}

	// Verify the key files were written
	keyPath := filepath.Join(configDir, "attestation-ed25519.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("private key file was not written")
	}
	pubPath := filepath.Join(configDir, "attestation-ed25519.pub")
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Fatal("public key file was not written")
	}

	// Verify the public key matches the private key
	pubPEM, _ := os.ReadFile(pubPath)
	block, _ := pem.Decode(pubPEM)
	pubAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pub := pubAny.(ed25519.PublicKey)

	testPayload := []byte("verification test")
	sig := ed25519.Sign(priv, testPayload)
	if !ed25519.Verify(pub, testPayload, sig) {
		t.Fatal("generated keypair: public key does not match private key")
	}
}

// TestLoadOrGenerateKeypair_LoadsExisting verifies loading an existing key.
func TestLoadOrGenerateKeypair_LoadsExisting(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	// Pre-generate and write a key
	_, origPriv, _ := ed25519.GenerateKey(nil)
	privDER, _ := x509.MarshalPKCS8PrivateKey(origPriv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	keyPath := filepath.Join(configDir, "attestation-ed25519.key")
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	priv, generated, err := loadOrGenerateKeypair(tmpDir)
	if err != nil {
		t.Fatalf("loadOrGenerateKeypair: %v", err)
	}
	if generated {
		t.Fatal("expected generated=false when key exists")
	}
	if !priv.Equal(origPriv) {
		t.Fatal("loaded key does not match original")
	}
}

// TestLoadOrGenerateKeypair_UsesEnvVar verifies ATTESTATION_PRIVATE_KEY env var.
func TestLoadOrGenerateKeypair_UsesEnvVar(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	// Write key to a non-standard location
	_, origPriv, _ := ed25519.GenerateKey(nil)
	privDER, _ := x509.MarshalPKCS8PrivateKey(origPriv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	customKeyPath := filepath.Join(tmpDir, "custom-location.key")
	if err := os.WriteFile(customKeyPath, privPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	t.Setenv("ATTESTATION_PRIVATE_KEY", customKeyPath)

	priv, generated, err := loadOrGenerateKeypair(tmpDir)
	if err != nil {
		t.Fatalf("loadOrGenerateKeypair: %v", err)
	}
	if generated {
		t.Fatal("expected generated=false when key exists at env var path")
	}
	if !priv.Equal(origPriv) {
		t.Fatal("loaded key does not match original written to custom path")
	}
}

// TestCopyFile verifies file copy works correctly.
func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "source.txt")
	dst := filepath.Join(tmpDir, "dest.txt")
	content := []byte("copy test content")

	if err := os.WriteFile(src, content, 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
}

// TestWritePublicKey verifies the public key is written in PEM PKIX format
// compatible with the gateway's verifyBlobSignature function.
func TestWritePublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(nil)
	if err := writePublicKey(tmpDir, pub); err != nil {
		t.Fatalf("writePublicKey: %v", err)
	}

	pubPath := filepath.Join(configDir, "attestation-ed25519.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM block in public key file")
		return
	}
	if block.Type != "PUBLIC KEY" {
		t.Fatalf("expected PEM type 'PUBLIC KEY', got %q", block.Type)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX public key: %v", err)
	}
	edPub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("parsed key is not Ed25519: %T", parsed)
	}
	if !pub.Equal(edPub) {
		t.Fatal("written public key does not match original")
	}
}

// TestSignAndVerify_FullRoundTrip tests the complete flow: generate keypair,
// sign an artifact, then verify using the exact same algorithm as the
// gateway's verifyBlobSignature (read PEM pub, decode base64 sig, ed25519.Verify).
func TestSignAndVerify_FullRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	// Step 1: Generate keypair
	priv, generated, err := loadOrGenerateKeypair(tmpDir)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	if !generated {
		t.Fatal("expected new keypair generation")
	}

	// Step 2: Write and sign a test artifact
	payload := []byte("hello world - attestation round-trip test")
	artifactPath := filepath.Join(tmpDir, "test.bin")
	if err := os.WriteFile(artifactPath, payload, 0644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if err := signArtifact(artifactPath, priv); err != nil {
		t.Fatalf("sign artifact: %v", err)
	}

	// Step 3: Verify using the same algorithm as verifyBlobSignature
	pubPEM, err := os.ReadFile(filepath.Join(configDir, "attestation-ed25519.pub"))
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		t.Fatal("no PEM block in public key")
		return
	}
	keyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	edKey, ok := keyAny.(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key is not Ed25519")
	}

	sigRaw, err := os.ReadFile(artifactPath + ".sig")
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(string(sigRaw))
	if err != nil {
		t.Fatalf("decode base64 sig: %v", err)
	}
	if !ed25519.Verify(edKey, payload, sig) {
		t.Fatal("full round-trip verification failed")
	}
}
