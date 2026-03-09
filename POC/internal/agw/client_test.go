package agw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientGetHealth_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","circuit_breaker":{"state":"closed"}}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	h, err := c.GetHealth(ctx)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", h.Status)
	}
	if h.CircuitBreakerState != "closed" {
		t.Fatalf("expected circuit_breaker.state=closed, got %q", h.CircuitBreakerState)
	}
}

func TestClientGetHealth_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	_, err := c.GetHealth(ctx)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
}

func TestClientResetCircuitBreakers_OK(t *testing.T) {
	var gotTool string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/circuit-breakers/reset" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body struct {
			Tool string `json:"tool"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid request body"}`))
			return
		}
		gotTool = body.Tool
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reset":[{"tool":"bash","previous_state":"open","new_state":"closed"}]}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	out, err := c.ResetCircuitBreakers(ctx, "bash")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if gotTool != "bash" {
		t.Fatalf("expected tool=bash in request body, got %q", gotTool)
	}
	if len(out.Reset) != 1 {
		t.Fatalf("expected one reset entry, got %+v", out.Reset)
	}
	if out.Reset[0].Tool != "bash" || out.Reset[0].PreviousState != "open" || out.Reset[0].NewState != "closed" {
		t.Fatalf("unexpected reset output: %+v", out.Reset[0])
	}
}

func TestClientResetCircuitBreakers_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unknown tool: nope"}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	_, err := c.ResetCircuitBreakers(ctx, "nope")
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool: nope") {
		t.Fatalf("expected unknown tool error, got %v", err)
	}
}

func TestClientReloadPolicy_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/policy/reload" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"reloaded","timestamp":"2026-02-11T10:00:00Z","registry_tools":5,"opa_policies":3,"cosign_verified":true}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	out, err := c.ReloadPolicy(ctx)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if out.Status != "reloaded" {
		t.Fatalf("expected status=reloaded, got %q", out.Status)
	}
	if out.RegistryTools != 5 || out.OPAPolicies != 3 {
		t.Fatalf("unexpected counts: %+v", out)
	}
	if !out.CosignVerified {
		t.Fatalf("expected cosign_verified=true, got false")
	}
}

func TestClientReloadPolicy_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"failed","error":"signature verification failed: no .sig file found for config/tool-registry.yaml","cosign_verified":false}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	_, err := c.ReloadPolicy(ctx)
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature verification error, got %v", err)
	}
}

func TestClientUpsertDLPRuleset_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/dlp/rulesets" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"created","active":{"version":"v2","digest":"abc","state":"draft","approved":false,"signed":false}}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	out, err := c.UpsertDLPRuleset(ctx, DLPRulesetUpsertInput{Version: "v2"})
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if out.Status != "created" || out.Active == nil || out.Active.Version != "v2" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestClientPromoteDLPRuleset_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"failed","error":"ruleset v2 is not approved/signed"}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	_, err := c.PromoteDLPRuleset(ctx, "v2")
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
	if !strings.Contains(err.Error(), "not approved/signed") {
		t.Fatalf("expected approval error, got %v", err)
	}
}

func TestClientListLoopRuns_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/loop/runs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","runs":[{"run_id":"run-1","session_id":"sess-1","tenant":"tenant-a","state":"RUNNING","limits":{"max_steps":5,"max_tool_calls":5,"max_model_calls":5,"max_wall_time_ms":60000,"max_egress_bytes":10000,"max_model_cost_usd":1.0,"max_provider_failovers":2,"max_risk_score":0.8},"usage":{"steps":1,"tool_calls":1,"model_calls":1,"wall_time_ms":100,"egress_bytes":10,"model_cost_usd":0.1,"provider_failovers":0,"risk_score":0.1},"updated_at":"2026-02-12T10:00:00Z"}]}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	out, err := c.ListLoopRuns(ctx)
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if out.Status != "ok" || len(out.Runs) != 1 || out.Runs[0].RunID != "run-1" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestClientGetLoopRun_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":"failed","error":"run not found"}`))
	}))
	t.Cleanup(ts.Close)

	c := NewClient(ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	_, err := c.GetLoopRun(ctx, "missing-run")
	if err == nil {
		t.Fatalf("expected err, got nil")
	}
	if !strings.Contains(err.Error(), "run not found") {
		t.Fatalf("expected run not found, got %v", err)
	}
}
