// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
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

func writePolicyTestFixtures(t *testing.T) (opaDir string, registryPath string) {
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
    risk_level: "medium"
    requires_step_up: false
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

func TestRunPolicyTestOffline_Allowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", out)
	}
	if len(out.Layers) != 6 {
		t.Fatalf("expected 6 layers, got %+v", out.Layers)
	}
	for i, layer := range out.Layers {
		if layer.Result != "PASS" {
			t.Fatalf("expected layer %d PASS, got %+v", i+1, layer)
		}
	}
}

func TestRunPolicyTestOffline_Layer1SizeFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	huge := `{"blob":"` + strings.Repeat("a", policyTestMaxRequestSizeBytes) + `"}`

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		huge,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 1 {
		t.Fatalf("expected layer-1 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer2BodyFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 2 {
		t.Fatalf("expected layer-2 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer3SpiffeFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://other.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 3 {
		t.Fatalf("expected layer-3 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer4RegistryFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"unknown_tool",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 4 {
		t.Fatalf("expected layer-4 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer5OPAFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/other/dev",
		"tavily_search",
		`{"query":"hello"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 5 {
		t.Fatalf("expected layer-5 denial, got %+v", out)
	}
}

func TestRunPolicyTestOffline_Layer6DLPFail(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	out, err := RunPolicyTestOffline(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"token":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}`,
		opaDir,
		registryPath,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestOffline failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 6 {
		t.Fatalf("expected layer-6 denial, got %+v", out)
	}
}

func TestRenderPolicyTestOfflineTableAndJSON(t *testing.T) {
	out := PolicyTestOfflineOutput{
		Mode:          "offline",
		SPIFFEID:      "spiffe://poc.local/agents/x/dev",
		Tool:          "tavily_search",
		Verdict:       "DENIED",
		BlockingLayer: 5,
		Note:          "Runtime layers 7-13 require --runtime flag with running stack",
		Layers: []PolicyTestLayer{
			{Step: 1, Layer: "Request Size Limit", Result: "PASS", Detail: "ok"},
			{Step: 5, Layer: "OPA Policy", Result: "FAIL", Detail: "denied"},
		},
	}

	table, err := RenderPolicyTestOfflineTable(out)
	if err != nil {
		t.Fatalf("RenderPolicyTestOfflineTable failed: %v", err)
	}
	for _, want := range []string{
		"DRY RUN (offline)",
		"STEP",
		"OPA Policy",
		"VERDICT: DENIED (blocked at layer 5)",
	} {
		if !strings.Contains(table, want) {
			t.Fatalf("expected table output to contain %q, got %q", want, table)
		}
	}

	b, err := RenderPolicyTestOfflineJSON(out)
	if err != nil {
		t.Fatalf("RenderPolicyTestOfflineJSON failed: %v", err)
	}
	if !strings.Contains(string(b), `"blocking_layer":5`) {
		t.Fatalf("expected blocking layer in json, got %s", string(b))
	}
	if !strings.Contains(string(b), fmt.Sprintf(`"tool":"%s"`, out.Tool)) {
		t.Fatalf("expected tool field in json, got %s", string(b))
	}
}

func TestRunPolicyTestRuntime_Allowed(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)

	mr := miniredis.RunT(t)
	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })

	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-runtime-ok"
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
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30,"last_state_change":null}]}`))
	}))
	t.Cleanup(ts.Close)

	t.Setenv("GUARD_API_KEY", "")

	out, err := RunPolicyTestRuntime(
		spiffeID,
		"tavily_search",
		`{"query":"runtime-ok"}`,
		opaDir,
		registryPath,
		"redis://"+mr.Addr(),
		ts.URL,
		sessionID,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestRuntime failed: %v", err)
	}
	if out.Verdict != "ALLOWED" {
		t.Fatalf("expected ALLOWED verdict, got %+v", out)
	}
	if len(out.Layers) != 13 {
		t.Fatalf("expected 13 layers, got %+v", out.Layers)
	}
	if out.Layers[6].Step != 7 || out.Layers[6].Result != "PASS" {
		t.Fatalf("expected layer 7 PASS, got %+v", out.Layers[6])
	}
	if out.Layers[8].Step != 9 || out.Layers[8].Result != "SKIP" {
		t.Fatalf("expected layer 9 SKIP (no GUARD_API_KEY), got %+v", out.Layers[8])
	}
	if out.Note != "" {
		t.Fatalf("expected empty note in runtime mode, got %q", out.Note)
	}
}

func TestRunPolicyTestRuntime_Layer7MissingSessionFails(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	mr := miniredis.RunT(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30}]}`))
	}))
	t.Cleanup(ts.Close)

	out, err := RunPolicyTestRuntime(
		"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev",
		"tavily_search",
		`{"query":"runtime"}`,
		opaDir,
		registryPath,
		"redis://"+mr.Addr(),
		ts.URL,
		"sid-not-found",
	)
	if err != nil {
		t.Fatalf("RunPolicyTestRuntime failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 7 {
		t.Fatalf("expected layer-7 denial, got %+v", out)
	}
}

func TestRunPolicyTestRuntime_Layer10RateLimitFails(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	mr := miniredis.RunT(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-rate-limit"

	if err := mr.Set("session:"+spiffeID+":"+sessionID, `{"RiskScore":0.10}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })
	if err := kdb.SetTokensForTest(context.Background(), spiffeID, 0.0, 30*time.Second); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30}]}`))
	}))
	t.Cleanup(ts.Close)

	out, err := RunPolicyTestRuntime(
		spiffeID,
		"tavily_search",
		`{"query":"runtime-rate-limit"}`,
		opaDir,
		registryPath,
		"redis://"+mr.Addr(),
		ts.URL,
		sessionID,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestRuntime failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 10 {
		t.Fatalf("expected layer-10 denial, got %+v", out)
	}
}

func TestRunPolicyTestRuntime_Layer11CircuitOpenFails(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	mr := miniredis.RunT(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-cb-open"

	if err := mr.Set("session:"+spiffeID+":"+sessionID, `{"RiskScore":0.10}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })
	if err := kdb.SetTokensForTest(context.Background(), spiffeID, 55.0, 30*time.Second); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"open","failures":5,"threshold":5,"reset_timeout_seconds":30}]}`))
	}))
	t.Cleanup(ts.Close)

	out, err := RunPolicyTestRuntime(
		spiffeID,
		"tavily_search",
		`{"query":"runtime-cb-open"}`,
		opaDir,
		registryPath,
		"redis://"+mr.Addr(),
		ts.URL,
		sessionID,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestRuntime failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 11 {
		t.Fatalf("expected layer-11 denial, got %+v", out)
	}
}

func TestRunPolicyTestRuntime_Layer12InvalidTokenSyntaxFails(t *testing.T) {
	opaDir, registryPath := writePolicyTestFixtures(t)
	mr := miniredis.RunT(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
	sessionID := "sid-token-invalid"

	if err := mr.Set("session:"+spiffeID+":"+sessionID, `{"RiskScore":0.10}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	kdb, err := NewKeyDB("redis://" + mr.Addr())
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { _ = kdb.Close() })
	if err := kdb.SetTokensForTest(context.Background(), spiffeID, 55.0, 30*time.Second); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"tavily_search","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30}]}`))
	}))
	t.Cleanup(ts.Close)

	out, err := RunPolicyTestRuntime(
		spiffeID,
		"tavily_search",
		`{"query":"$SPIKE{ref:nothex}"}`,
		opaDir,
		registryPath,
		"redis://"+mr.Addr(),
		ts.URL,
		sessionID,
	)
	if err != nil {
		t.Fatalf("RunPolicyTestRuntime failed: %v", err)
	}
	if out.Verdict != "DENIED" || out.BlockingLayer != 12 {
		t.Fatalf("expected layer-12 denial, got %+v", out)
	}
}
