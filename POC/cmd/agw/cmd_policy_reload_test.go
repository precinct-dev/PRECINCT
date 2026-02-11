package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgwPolicyReload_ConfirmRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"policy", "reload"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--confirm is required for policy reload") {
		t.Fatalf("expected confirm-required error, got %q", stderr.String())
	}
}

func TestAgwPolicyReload_SuccessTable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/policy/reload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"reloaded","timestamp":"2026-02-11T10:00:00Z","registry_tools":5,"opa_policies":3,"cosign_verified":true}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"policy", "reload", "--confirm", "--gateway-url", ts.URL},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Policy reload successful") {
		t.Fatalf("expected success banner, got %q", out)
	}
	if !strings.Contains(out, "Tool registry: 5 tools loaded (cosign verified)") {
		t.Fatalf("expected tool count/cosign line, got %q", out)
	}
	if !strings.Contains(out, "OPA policies: 3 policies loaded") {
		t.Fatalf("expected OPA count line, got %q", out)
	}
	if !strings.Contains(out, "Timestamp: 2026-02-11T10:00:00Z") {
		t.Fatalf("expected timestamp line, got %q", out)
	}
}

func TestAgwPolicyReload_SuccessJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"reloaded","timestamp":"2026-02-11T10:00:00Z","registry_tools":7,"opa_policies":4,"cosign_verified":false}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"policy", "reload", "--confirm", "--gateway-url", ts.URL, "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Status         string `json:"status"`
		RegistryTools  int    `json:"registry_tools"`
		OPAPolicies    int    `json:"opa_policies"`
		CosignVerified bool   `json:"cosign_verified"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid json output, got err=%v raw=%q", err, stdout.String())
	}
	if parsed.Status != "reloaded" || parsed.RegistryTools != 7 || parsed.OPAPolicies != 4 || parsed.CosignVerified {
		t.Fatalf("unexpected parsed json: %+v", parsed)
	}
}

func TestAgwPolicyReload_CosignFailureMessage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"failed","error":"signature verification failed: no .sig file found for config/tool-registry.yaml","cosign_verified":false}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"policy", "reload", "--confirm", "--gateway-url", ts.URL},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "ERROR: Policy reload failed") {
		t.Fatalf("expected explicit reload failure message, got %q", errOut)
	}
	if !strings.Contains(errOut, "Reason: signature verification failed") {
		t.Fatalf("expected signature reason in error, got %q", errOut)
	}
	if !strings.Contains(errOut, "cosign sign-blob --key <private-key> config/tool-registry.yaml > config/tool-registry.yaml.sig") {
		t.Fatalf("expected cosign fix guidance, got %q", errOut)
	}
}
