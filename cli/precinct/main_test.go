// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestPrecinctStatus_JSON_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","circuit_breaker":{"state":"closed"}}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--component", "gateway", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}

	// AC3: Valid JSON output
	var parsed struct {
		Components []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"components"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v; raw=%q", err, stdout.String())
	}
	if len(parsed.Components) != 1 || parsed.Components[0].Name != "gateway" || parsed.Components[0].Status != "ok" {
		t.Fatalf("unexpected parsed JSON: %+v", parsed)
	}
}

func TestPrecinctInspectIdentity_JSON(t *testing.T) {
	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	grants := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools: ["read"]
    max_data_classification: internal
    requires_approval_for: ["bash"]
`
	registry := `tools:
  - name: "read"
    risk_level: "low"
    requires_step_up: false
  - name: "bash"
    risk_level: "critical"
    requires_step_up: true
`
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(grants), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	registryPath := filepath.Join(tmp, "tool-registry.yaml")
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"inspect", "identity", "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--format", "json",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		SPIFFEID      string `json:"spiffe_id"`
		MatchedGrants []struct {
			SPIFFEPattern string `json:"spiffe_pattern"`
		} `json:"matched_grants"`
		Tools []struct {
			Tool       string `json:"tool"`
			Authorized bool   `json:"authorized"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v output=%q", err, stdout.String())
	}
	if parsed.SPIFFEID == "" || len(parsed.MatchedGrants) == 0 || len(parsed.Tools) == 0 {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestPrecinctInspectIdentity_NoMatch_Exit1(t *testing.T) {
	tmp := t.TempDir()
	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(`tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/*"
    description: "agents"
    allowed_tools: ["read"]
    max_data_classification: internal
    requires_approval_for: []
`), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	registryPath := filepath.Join(tmp, "tool-registry.yaml")
	if err := os.WriteFile(registryPath, []byte(`tools:
  - name: "read"
    risk_level: "low"
    requires_step_up: false
`), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"inspect", "identity", "spiffe://different.domain/agent/dev",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "no matching grants") {
		t.Fatalf("expected no matching grants error, got %q", stderr.String())
	}
}

func TestPrecinctInspectSessions_JSON(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionKey := "session:" + spiffeID + ":sid-test"
	if err := mr.Set(sessionKey, `{"ID":"sid-test","SPIFFEID":"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev","RiskScore":0.65}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	mr.SetTTL(sessionKey, 30*time.Minute)
	if _, err := mr.RPush(sessionKey+":actions", `{"Tool":"read"}`, `{"Tool":"grep"}`); err != nil {
		t.Fatalf("seed actions: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"inspect", "sessions", spiffeID,
			"--keydb-url", fmt.Sprintf("redis://%s", mr.Addr()),
			"--format", "json",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Sessions []struct {
			SessionID     string  `json:"session_id"`
			SPIFFEID      string  `json:"spiffe_id"`
			RiskScore     float64 `json:"risk_score"`
			ToolsAccessed int     `json:"tools_accessed"`
			TTLSeconds    int     `json:"ttl_seconds"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v output=%q", err, stdout.String())
	}
	if len(parsed.Sessions) != 1 {
		t.Fatalf("expected one session, got %+v", parsed.Sessions)
	}
	got := parsed.Sessions[0]
	if got.SPIFFEID != spiffeID || got.SessionID != "sid-test" {
		t.Fatalf("unexpected session data: %+v", got)
	}
	if got.ToolsAccessed != 2 {
		t.Fatalf("expected tools_accessed=2, got %+v", got)
	}
}

func TestPrecinctStatus_Table_Default(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","circuit_breaker":{"state":"closed"}}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--component", "gateway", "--gateway-url", ts.URL}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	s := stdout.String()
	// AC4: Table mode is default, human readable.
	if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "gateway") || !strings.Contains(s, "OK") {
		t.Fatalf("unexpected table output:\n%s", s)
	}
}

func TestPrecinctStatus_Unreachable_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--component", "gateway", "--gateway-url", "http://127.0.0.1:1", "--format", "table"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
}

func TestPrecinctResetRateLimit_AllWithoutConfirm_Fails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "rate-limit", "--all", "--keydb-url", "redis://localhost:6379"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--all requires --confirm") {
		t.Fatalf("expected --all requires --confirm error, got %q", stderr.String())
	}
}

func TestPrecinctResetRateLimit_PromptNo_Aborts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "rate-limit", "spiffe://poc.local/agents/test/dev", "--keydb-url", "redis://localhost:6379"},
		strings.NewReader("\n"), // default [y/N] => no
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "aborted") {
		t.Fatalf("expected aborted, got %q", stderr.String())
	}
}

func TestPrecinctResetRateLimit_PromptYes_DeletesKeys(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	spiffe := "spiffe://poc.local/agents/test/dev"
	if err := mr.Set("ratelimit:"+spiffe+":tokens", "1.5"); err != nil {
		t.Fatalf("seed rate limit tokens: %v", err)
	}
	if err := mr.Set("ratelimit:"+spiffe+":last_fill", "123"); err != nil {
		t.Fatalf("seed rate limit last_fill: %v", err)
	}

	keydbURL := fmt.Sprintf("redis://%s", mr.Addr())

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "rate-limit", spiffe, "--keydb-url", keydbURL},
		strings.NewReader("y\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Deleted 2 rate limit keys") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if mr.Exists("ratelimit:"+spiffe+":tokens") || mr.Exists("ratelimit:"+spiffe+":last_fill") {
		t.Fatalf("expected ratelimit keys deleted")
	}
}

func TestPrecinctResetRateLimit_AllConfirm_DeletesOnlyRatelimit(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	if err := mr.Set("ratelimit:spiffe://a:tokens", "1"); err != nil {
		t.Fatalf("seed rate limit tokens: %v", err)
	}
	if err := mr.Set("ratelimit:spiffe://a:last_fill", "1"); err != nil {
		t.Fatalf("seed rate limit last_fill: %v", err)
	}
	if err := mr.Set("session:spiffe://a", "keep"); err != nil {
		t.Fatalf("seed session key: %v", err)
	}

	keydbURL := fmt.Sprintf("redis://%s", mr.Addr())

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "rate-limit", "--all", "--confirm", "--keydb-url", keydbURL},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "pattern=ratelimit:*") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if mr.Exists("ratelimit:spiffe://a:tokens") || mr.Exists("ratelimit:spiffe://a:last_fill") {
		t.Fatalf("expected ratelimit keys deleted")
	}
	if !mr.Exists("session:spiffe://a") {
		t.Fatalf("expected non-ratelimit keys to remain")
	}
}

func TestPrecinctAuditSearch_FileSource_JSONDecisionID(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	lines := []string{
		`{"timestamp":"2026-02-11T09:00:00Z","decision_id":"d-1","spiffe_id":"spiffe://poc.local/agents/a/dev","tool":"tavily_search","result":"allowed","status_code":200}`,
		`{"timestamp":"2026-02-11T09:10:00Z","decision_id":"d-2","spiffe_id":"spiffe://poc.local/agents/b/dev","tool":"bash","result":"denied","status_code":403}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"audit", "search",
			"--source", "file",
			"--audit-log-path", logPath,
			"--decision-id", "d-2",
			"--format", "json",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed []struct {
		DecisionID string `json:"decision_id"`
		Tool       string `json:"tool"`
		Result     string `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v output=%q", err, stdout.String())
	}
	if len(parsed) != 1 {
		t.Fatalf("expected one result, got %+v", parsed)
	}
	if parsed[0].DecisionID != "d-2" || parsed[0].Tool != "bash" || parsed[0].Result != "denied" {
		t.Fatalf("unexpected result: %+v", parsed[0])
	}
}

func TestPrecinctAuditSearch_InvalidLast_Exit1(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"timestamp":"2026-02-11T09:00:00Z","decision_id":"d-1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"audit", "search",
			"--source", "file",
			"--audit-log-path", logPath,
			"--last", "9x",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid --last") {
		t.Fatalf("expected invalid --last error, got %q", stderr.String())
	}
}

func TestPrecinctAuditExplain_FileSource_JSON(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	lines := []string{
		`{"timestamp":"2026-02-11T09:10:00Z","decision_id":"dec-explain","spiffe_id":"spiffe://poc.local/agents/a/dev","tool":"bash","action":"mcp_request","status_code":403,"code":"registry_tool_unknown"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"audit", "explain", "dec-explain",
			"--source", "file",
			"--audit-log-path", logPath,
			"--format", "json",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		DecisionID string `json:"decision_id"`
		Result     string `json:"result"`
		Layers     []struct {
			Step   int    `json:"step"`
			Status string `json:"status"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v output=%q", err, stdout.String())
	}
	if parsed.DecisionID != "dec-explain" {
		t.Fatalf("unexpected decision id: %+v", parsed)
	}
	if !strings.Contains(parsed.Result, "denied") {
		t.Fatalf("expected denied result, got %+v", parsed)
	}
	if len(parsed.Layers) != 13 {
		t.Fatalf("expected 13 layers, got %+v", parsed.Layers)
	}
}

func TestPrecinctAuditExplain_NotFound_Exit1(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "audit.jsonl")
	if err := os.WriteFile(logPath, []byte(`{"decision_id":"other"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"audit", "explain", "missing-decision",
			"--source", "file",
			"--audit-log-path", logPath,
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "no audit entries found") {
		t.Fatalf("expected not found error, got %q", stderr.String())
	}
}
