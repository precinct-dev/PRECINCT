// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

// Command attestation-sign generates or loads an Ed25519 keypair and signs
// configuration artifacts used by the PRECINCT Gateway for attestation.
//
// Usage:
//
//	go run ./cmd/attestation-sign [options]
//
// The tool signs three artifacts:
//   - config/tool-registry.yaml
//   - config/model-provider-catalog.v2.yaml
//   - config/guard-artifact.bin
//
// Each artifact gets a companion .sig file containing the base64-encoded
// Ed25519 signature. All three share a single public key written to
// config/attestation-ed25519.pub.
//
// The private key is read from config/attestation-ed25519.key or the path
// specified by $ATTESTATION_PRIVATE_KEY. If no private key exists, a new
// Ed25519 keypair is generated and written to disk.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// artifacts lists the config files that require Ed25519 signatures.
// Includes both top-level configs and OPA policy files.
var artifacts = []string{
	"config/tool-registry.yaml",
	"config/model-provider-catalog.v2.yaml",
	"config/guard-artifact.bin",
}

// opaPolicyDir contains .rego and .yaml files that need signing for
// OPA hot-reload attestation.
const opaPolicyDir = "config/opa"

// k8sOverlayDir is the relative path to the K8s local overlay gateway-config.
const k8sOverlayDir = "deploy/terraform/overlays/local/gateway-config"

func main() {
	projectRoot, err := findProjectRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	privKey, generated, err := loadOrGenerateKeypair(projectRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if generated {
		fmt.Println("Generated new Ed25519 keypair:")
		fmt.Printf("  Private key: %s\n", filepath.Join(projectRoot, "config", "attestation-ed25519.key"))
		fmt.Printf("  Public key:  %s\n", filepath.Join(projectRoot, "config", "attestation-ed25519.pub"))
	} else {
		fmt.Println("Using existing Ed25519 private key")
	}

	fmt.Println()
	fmt.Println("Signing artifacts:")
	for _, relPath := range artifacts {
		absPath := filepath.Join(projectRoot, relPath)
		if err := signArtifact(absPath, privKey); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR signing %s: %v\n", relPath, err)
			os.Exit(1)
		}
		fmt.Printf("  [SIGNED] %s -> %s.sig\n", relPath, relPath)
	}

	// Sign OPA policy files (.rego and .yaml in config/opa/)
	fmt.Println()
	fmt.Println("Signing OPA policy files:")
	opaDir := filepath.Join(projectRoot, opaPolicyDir)
	entries, err := os.ReadDir(opaDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading OPA policy dir: %v\n", err)
		os.Exit(1)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".rego" && ext != ".yaml" && ext != ".yml" {
			continue
		}
		absPath := filepath.Join(opaDir, entry.Name())
		if err := signArtifact(absPath, privKey); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR signing %s: %v\n", entry.Name(), err)
			os.Exit(1)
		}
		fmt.Printf("  [SIGNED] %s/%s -> %s/%s.sig\n", opaPolicyDir, entry.Name(), opaPolicyDir, entry.Name())
	}

	// Copy .pub and .sig files to K8s overlay
	fmt.Println()
	fmt.Println("Copying to K8s overlay:")
	overlayDir := filepath.Join(projectRoot, k8sOverlayDir)
	if _, err := os.Stat(overlayDir); os.IsNotExist(err) {
		fmt.Printf("  WARNING: K8s overlay directory does not exist: %s (skipping)\n", k8sOverlayDir)
	} else {
		filesToCopy := []string{"config/attestation-ed25519.pub"}
		for _, a := range artifacts {
			filesToCopy = append(filesToCopy, a+".sig")
		}
		for _, relPath := range filesToCopy {
			src := filepath.Join(projectRoot, relPath)
			dst := filepath.Join(overlayDir, filepath.Base(relPath))
			if err := copyFile(src, dst); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR copying %s: %v\n", relPath, err)
				os.Exit(1)
			}
			fmt.Printf("  [COPIED] %s -> %s/%s\n", filepath.Base(relPath), k8sOverlayDir, filepath.Base(relPath))
		}
	}

	fmt.Println()
	if generated {
		fmt.Println("Summary: New keypair generated and all artifacts signed.")
	} else {
		fmt.Println("Summary: All artifacts re-signed with existing keypair.")
	}
}

// findProjectRoot walks up from the current working directory to find go.mod.
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

// loadOrGenerateKeypair loads an existing Ed25519 private key or generates a
// new keypair. Returns the private key and whether a new keypair was generated.
func loadOrGenerateKeypair(projectRoot string) (ed25519.PrivateKey, bool, error) {
	keyPath := resolvePrivateKeyPath(projectRoot)

	if data, err := os.ReadFile(keyPath); err == nil {
		privKey, err := parsePrivateKeyPEM(data)
		if err != nil {
			return nil, false, fmt.Errorf("parse private key %s: %w", keyPath, err)
		}
		return privKey, false, nil
	}

	// Generate new keypair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, false, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}

	// Write private key (PKCS8 PEM)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, false, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	defaultKeyPath := filepath.Join(projectRoot, "config", "attestation-ed25519.key")
	if err := os.WriteFile(defaultKeyPath, privPEM, 0600); err != nil {
		return nil, false, fmt.Errorf("write private key: %w", err)
	}

	// Write public key (PKIX PEM)
	if err := writePublicKey(projectRoot, pub); err != nil {
		return nil, false, err
	}

	return priv, true, nil
}

// resolvePrivateKeyPath checks the env var first, then the default location.
func resolvePrivateKeyPath(projectRoot string) string {
	if envPath := strings.TrimSpace(os.Getenv("ATTESTATION_PRIVATE_KEY")); envPath != "" {
		return envPath
	}
	return filepath.Join(projectRoot, "config", "attestation-ed25519.key")
}

// writePublicKey writes the Ed25519 public key as PEM PKIX.
func writePublicKey(projectRoot string, pub ed25519.PublicKey) error {
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath := filepath.Join(projectRoot, "config", "attestation-ed25519.pub")
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// parsePrivateKeyPEM decodes a PEM PKCS8 Ed25519 private key.
func parsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8: %w", err)
	}
	edKey, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", keyAny)
	}
	return edKey, nil
}

// signArtifact reads a file, signs it with the Ed25519 private key, and
// writes the base64-encoded signature to <path>.sig.
func signArtifact(path string, privKey ed25519.PrivateKey) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	sig := ed25519.Sign(privKey, content)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	if err := os.WriteFile(path+".sig", []byte(sigB64), 0644); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	return os.WriteFile(dst, data, 0644)
}
