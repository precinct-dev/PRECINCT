// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretInit_CreatesStorage(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, ".spike", "secrets.json")
	t.Setenv("HOME", tmpDir)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "init"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "SUCCESS: SPIKE Nexus initialized") {
		t.Fatalf("expected success message, got %q", out)
	}
	if !strings.Contains(out, "precinct secret put") {
		t.Fatalf("expected next steps to reference 'precinct secret put', got %q", out)
	}
	if !strings.Contains(out, "precinct secret issue") {
		t.Fatalf("expected next steps to reference 'precinct secret issue', got %q", out)
	}

	// Verify storage dir was created
	dir := filepath.Dir(storagePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Errorf("storage directory was not created: %s", dir)
	}
}
