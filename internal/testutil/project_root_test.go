package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectRoot(t *testing.T) {
	root := ProjectRoot()

	if root == "" {
		t.Fatal("ProjectRoot() returned empty string")
	}

	if !filepath.IsAbs(root) {
		t.Errorf("ProjectRoot() returned non-absolute path: %s", root)
	}

	// Verify go.mod exists at the root
	goModPath := filepath.Join(root, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		t.Errorf("go.mod not found at project root %s: %v", root, err)
	}
}

func TestProjectRoot_Idempotent(t *testing.T) {
	root1 := ProjectRoot()
	root2 := ProjectRoot()

	if root1 != root2 {
		t.Errorf("ProjectRoot() not idempotent: %q != %q", root1, root2)
	}
}

func TestOPAPolicyDir(t *testing.T) {
	dir := OPAPolicyDir()

	if !strings.HasSuffix(dir, filepath.Join("config", "opa")) {
		t.Errorf("OPAPolicyDir() has unexpected suffix: %s", dir)
	}

	// Verify the directory actually exists
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("OPA policy directory does not exist at %s: %v", dir, err)
	}
}

func TestOPAPolicyPath(t *testing.T) {
	path := OPAPolicyPath()

	if !strings.HasSuffix(path, filepath.Join("config", "opa", "mcp_policy.rego")) {
		t.Errorf("OPAPolicyPath() has unexpected suffix: %s", path)
	}

	// Verify the file actually exists
	if _, err := os.Stat(path); err != nil {
		t.Errorf("OPA policy file does not exist at %s: %v", path, err)
	}
}

func TestToolRegistryConfigPath(t *testing.T) {
	path := ToolRegistryConfigPath()

	if !strings.HasSuffix(path, filepath.Join("config", "tool-registry.yaml")) {
		t.Errorf("ToolRegistryConfigPath() has unexpected suffix: %s", path)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("Tool registry config does not exist at %s: %v", path, err)
	}
}

func TestUICapabilityGrantsPath(t *testing.T) {
	path := UICapabilityGrantsPath()

	if !strings.HasSuffix(path, filepath.Join("config", "opa", "ui_capability_grants.yaml")) {
		t.Errorf("UICapabilityGrantsPath() has unexpected suffix: %s", path)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("UI capability grants file does not exist at %s: %v", path, err)
	}
}
