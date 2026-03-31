package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/precinct-dev/precinct/internal/precinctcli"
)

func writePolicyTestCLIConfig(t *testing.T) (opaDir string, registryPath string) {
	t.Helper()

	tmp := t.TempDir()
	opaDir = filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir opa dir: %v", err)
	}

	grants := `tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools: ["tavily_search"]
    max_data_classification: internal
    requires_approval_for: []
`
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(grants), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}

	registryPath = filepath.Join(tmp, "tool-registry.yaml")
	registry := `tools:
  - name: "tavily_search"
    hash: "76c6b3d8a7ddbc387ca87aa784e99354feeda1ff438768cd99232a6772cceac0"
`
	if err := os.WriteFile(registryPath, []byte(registry), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	riskPath := filepath.Join(tmp, "risk_thresholds.yaml")
	riskCfg := `thresholds:
  fast_path_max: 3
  step_up_max: 6
  approval_max: 9
guard:
  injection_threshold: 0.30
  jailbreak_threshold: 0.30
unknown_tool_defaults:
  impact: 2
  reversibility: 2
  exposure: 2
  novelty: 3
dlp:
  credentials: block
  injection: flag
  pii: flag
`
	if err := os.WriteFile(riskPath, []byte(riskCfg), 0o644); err != nil {
		t.Fatalf("write risk config: %v", err)
	}
	return opaDir, registryPath
}

func TestPrecinctPolicyTest_JSONAllowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestCLIConfig(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "test",
			"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"tavily_search",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--params", `{"query":"hello"}`,
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
		Verdict string `json:"verdict"`
		Layers  []struct {
			Step   int    `json:"step"`
			Result string `json:"result"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v raw=%q", err, stdout.String())
	}
	if parsed.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", parsed)
	}
	if len(parsed.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %+v", parsed.Layers)
	}
}

func TestPrecinctPolicyTest_TableDenied(t *testing.T) {
	opaDir, registryPath := writePolicyTestCLIConfig(t)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "test",
			"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
			"unknown_tool",
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--format", "table",
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "DRY RUN (offline)") {
		t.Fatalf("expected dry-run heading, got %q", out)
	}
	if !strings.Contains(out, "VERDICT: DENIED (blocked at layer 4)") {
		t.Fatalf("expected denied verdict, got %q", out)
	}
	if !strings.Contains(out, "NOTE: Runtime layers 7-13 require --runtime flag with running stack") {
		t.Fatalf("expected runtime note, got %q", out)
	}
}

func TestPrecinctPolicyTest_RuntimeJSONAllowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestCLIConfig(t)

	mr := miniredis.RunT(t)
	kdb, err := precinctcli.NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-runtime-cli"
	if err := mr.Set("session:"+spiffeID+":"+sessionID, `{"RiskScore":0.15}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := kdb.SetTokensForTest(context.Background(), spiffeID, 55.0, 30*time.Second); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/circuit-breakers/tavily_search" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30}]}`))
	}))
	t.Cleanup(ts.Close)

	t.Setenv("GUARD_API_KEY", "")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{
			"policy", "test",
			spiffeID,
			"tavily_search",
			"--runtime",
			"--session-id", sessionID,
			"--opa-policy-dir", opaDir,
			"--tool-registry", registryPath,
			"--gateway-url", ts.URL,
			"--keydb-url", "redis://" + mr.Addr(),
			"--params", `{"query":"hello-runtime"}`,
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
		Mode          string `json:"mode"`
		Verdict       string `json:"verdict"`
		BlockingLayer int    `json:"blocking_layer"`
		Note          string `json:"note"`
		Layers        []struct {
			Step   int    `json:"step"`
			Result string `json:"result"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid runtime JSON output: %v raw=%q", err, stdout.String())
	}
	if parsed.Mode != "full" {
		t.Fatalf("expected mode=full, got %+v", parsed)
	}
	if parsed.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", parsed)
	}
	if parsed.BlockingLayer != 0 {
		t.Fatalf("expected blocking layer 0, got %+v", parsed)
	}
	if parsed.Note != "" {
		t.Fatalf("expected empty runtime note, got %+v", parsed)
	}
	if len(parsed.Layers) != 13 {
		t.Fatalf("expected 13 layers, got %+v", parsed.Layers)
	}
}
