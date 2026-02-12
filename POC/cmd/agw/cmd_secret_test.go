package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/example/agentic-security-poc/internal/agw"
)

type fakeSPIKEManager struct {
	listRefs []agw.SPIKESecretRef
	listErr  error

	putResult agw.SPIKESecretPutResult
	putErr    error
	putRef    string
	putValue  string
}

func (f *fakeSPIKEManager) ListSecretRefs(_ context.Context) ([]agw.SPIKESecretRef, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listRefs, nil
}

func (f *fakeSPIKEManager) PutSecret(_ context.Context, ref, value string) (agw.SPIKESecretPutResult, error) {
	f.putRef = ref
	f.putValue = value
	if f.putErr != nil {
		return agw.SPIKESecretPutResult{}, f.putErr
	}
	return f.putResult, nil
}

func withFakeSPIKEManager(t *testing.T, mgr spikeManager) {
	t.Helper()
	orig := newSPIKEManager
	newSPIKEManager = func() spikeManager { return mgr }
	t.Cleanup(func() { newSPIKEManager = orig })
}

func TestAgwSecretPut_ConfirmRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "put", "deadbeef", "super-secret"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "--confirm is required for secret put") {
		t.Fatalf("expected confirm-required error, got %q", errOut)
	}
	if strings.Contains(errOut, "super-secret") || strings.Contains(stdout.String(), "super-secret") {
		t.Fatalf("secret value leaked in output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAgwSecretList_JSON(t *testing.T) {
	withFakeSPIKEManager(t, &fakeSPIKEManager{
		listRefs: []agw.SPIKESecretRef{
			{Ref: "a1b2c3d4", Created: "-", Type: "string"},
			{Ref: "deadbeef", Created: "-", Type: "string"},
		},
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "list", "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Secrets []struct {
			Ref string `json:"ref"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if len(parsed.Secrets) != 2 {
		t.Fatalf("expected 2 refs, got %+v", parsed)
	}
	if parsed.Secrets[0].Ref == "" || parsed.Secrets[1].Ref == "" {
		t.Fatalf("expected refs in output, got %+v", parsed)
	}
}

func TestAgwSecretList_TableDefault(t *testing.T) {
	withFakeSPIKEManager(t, &fakeSPIKEManager{
		listRefs: []agw.SPIKESecretRef{
			{Ref: "deadbeef", Created: "-", Type: "string"},
		},
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "list"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "REF") || !strings.Contains(out, "TYPE") || !strings.Contains(out, "deadbeef") {
		t.Fatalf("unexpected table output: %q", out)
	}
}

func TestAgwSecretPut_SuccessAndNoValueLeak(t *testing.T) {
	fake := &fakeSPIKEManager{
		putResult: agw.SPIKESecretPutResult{
			Status: "stored",
			Ref:    "deadbeef",
		},
	}
	withFakeSPIKEManager(t, fake)

	const value = "super-secret-value"
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "put", "deadbeef", value, "--confirm"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if fake.putRef != "deadbeef" || fake.putValue != value {
		t.Fatalf("unexpected put args: ref=%q value=%q", fake.putRef, fake.putValue)
	}
	out := stdout.String()
	if !strings.Contains(out, "Secret stored successfully") || !strings.Contains(out, "REF: deadbeef") {
		t.Fatalf("unexpected put table output: %q", out)
	}
	if strings.Contains(out, value) || strings.Contains(stderr.String(), value) {
		t.Fatalf("secret value leaked in output: stdout=%q stderr=%q", out, stderr.String())
	}
}

func TestAgwSecretList_ErrorPropagates(t *testing.T) {
	withFakeSPIKEManager(t, &fakeSPIKEManager{
		listErr: errors.New("docker compose failed"),
	})

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"secret", "list"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "docker compose failed") {
		t.Fatalf("expected manager error in stderr, got %q", stderr.String())
	}
}
