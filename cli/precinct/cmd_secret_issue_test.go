package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/spike"
)

func TestSecretIssue_Success(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, ".spike", "secrets.json")
	t.Setenv("HOME", tmpDir)

	// Seed a secret first
	client := spike.NewClient(&spike.Config{StoragePath: storagePath})
	if err := client.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := client.Put(&spike.Secret{Ref: "abc123", Value: "test-value"}); err != nil {
		t.Fatalf("put: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "issue", "abc123", "--exp", "600", "--scope", "tools.http.api.openai.com"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "SUCCESS: Token issued") {
		t.Fatalf("expected success message, got %q", out)
	}
	if !strings.Contains(out, "$SPIKE{ref:abc123") {
		t.Fatalf("expected token with ref in output, got %q", out)
	}
	if !strings.Contains(out, "exp:600") {
		t.Fatalf("expected exp:600 in token, got %q", out)
	}
	if !strings.Contains(out, "scope:tools.http.api.openai.com") {
		t.Fatalf("expected scope in token, got %q", out)
	}
}

func TestSecretIssue_NonExistentRef_Exit1(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, ".spike", "secrets.json")
	t.Setenv("HOME", tmpDir)

	// Initialize storage but do not seed any secret
	client := spike.NewClient(&spike.Config{StoragePath: storagePath})
	if err := client.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "issue", "nonexistent"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "failed to issue token") {
		t.Fatalf("expected error message, got stderr=%q", stderr.String())
	}
}

func TestSecretIssue_MissingArg_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "issue"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
}

func TestSecretIssue_DefaultExp(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, ".spike", "secrets.json")
	t.Setenv("HOME", tmpDir)

	client := spike.NewClient(&spike.Config{StoragePath: storagePath})
	if err := client.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := client.Put(&spike.Secret{Ref: "def456", Value: "val"}); err != nil {
		t.Fatalf("put: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "issue", "def456"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	out := stdout.String()
	// Default exp is 300
	if !strings.Contains(out, "exp:300") {
		t.Fatalf("expected default exp:300 in token, got %q", out)
	}
}
