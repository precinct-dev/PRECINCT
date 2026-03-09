package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgwInspectModel_JSONFromFile(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	now := time.Now().UTC().Format(time.RFC3339)

	lines := []string{
		`{"timestamp":"` + now + `","action":"uasgs_plane_ingress","status_code":200,"decision_id":"dec-1","spiffe_id":"spiffe://poc.local/agent"}`,
		`{"timestamp":"` + now + `","action":"uasgs_plane_model","status_code":200,"decision_id":"dec-2","spiffe_id":"spiffe://poc.local/agent"}`,
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write audit file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"inspect", "model", "--source", "file", "--audit-log-path", auditPath, "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v output=%q", err, stdout.String())
	}
	if len(parsed) != 1 {
		t.Fatalf("expected one model entry, got %+v", parsed)
	}
	if parsed[0]["action"] != "uasgs_plane_model" {
		t.Fatalf("unexpected action in output: %+v", parsed[0])
	}
}

func TestAgwInspectIngress_DeniedOnly(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	now := time.Now().UTC().Format(time.RFC3339)

	lines := []string{
		`{"timestamp":"` + now + `","action":"uasgs_plane_ingress","status_code":200,"decision_id":"dec-ok","spiffe_id":"spiffe://poc.local/agent"}`,
		`{"timestamp":"` + now + `","action":"uasgs_plane_ingress","status_code":403,"decision_id":"dec-deny","spiffe_id":"spiffe://poc.local/agent","result":"deny:INGRESS_SCHEMA_INVALID"}`,
	}
	if err := os.WriteFile(auditPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatalf("write audit file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"inspect", "ingress", "--source", "file", "--audit-log-path", auditPath, "--denied", "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v output=%q", err, stdout.String())
	}
	if len(parsed) != 1 {
		t.Fatalf("expected one denied ingress entry, got %+v", parsed)
	}
	if parsed[0]["decision_id"] != "dec-deny" {
		t.Fatalf("expected denied entry, got %+v", parsed[0])
	}
}

func TestAgwInspectContext_Table(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	now := time.Now().UTC().Format(time.RFC3339)

	line := `{"timestamp":"` + now + `","action":"uasgs_plane_context","status_code":200,"decision_id":"dec-ctx","spiffe_id":"spiffe://poc.local/agent"}`
	if err := os.WriteFile(auditPath, []byte(line), 0o644); err != nil {
		t.Fatalf("write audit file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"inspect", "context", "--source", "file", "--audit-log-path", auditPath},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "DECISION_ID") || !strings.Contains(stdout.String(), "dec-ctx") {
		t.Fatalf("unexpected table output: %q", stdout.String())
	}
}

func TestAgwInspectRuleOps_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/dlp/rulesets" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","active":{"version":"v2","digest":"abc","state":"active","approved":true,"signed":true},"rulesets":[{"version":"v2","digest":"abc","state":"active","approved":true,"signed":true}]}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"inspect", "ruleops", "--gateway-url", ts.URL, "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v output=%q", err, stdout.String())
	}
	if parsed["status"] != "ok" {
		t.Fatalf("expected status ok, got %+v", parsed)
	}
}
