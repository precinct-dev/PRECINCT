package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgwInspectLoop_JSON_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/loop/runs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","runs":[{"run_id":"run-1","session_id":"sess-1","tenant":"tenant-a","state":"RUNNING","halt_reason":"","limits":{"max_steps":5,"max_tool_calls":5,"max_model_calls":5,"max_wall_time_ms":60000,"max_egress_bytes":10000,"max_model_cost_usd":1.0,"max_provider_failovers":2,"max_risk_score":0.8},"usage":{"steps":1,"tool_calls":1,"model_calls":1,"wall_time_ms":100,"egress_bytes":10,"model_cost_usd":0.1,"provider_failovers":0,"risk_score":0.1},"updated_at":"2026-02-12T10:00:00Z"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "loop", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}

	var parsed struct {
		Runs []struct {
			RunID string `json:"run_id"`
			State string `json:"state"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v raw=%q", err, stdout.String())
	}
	if len(parsed.Runs) != 1 || parsed.Runs[0].RunID != "run-1" || parsed.Runs[0].State != "RUNNING" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestAgwInspectLoop_RunID_Table(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/loop/runs/run-abc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","run":{"run_id":"run-abc","session_id":"sess-1","tenant":"tenant-a","state":"HALTED_BUDGET","halt_reason":"LOOP_HALT_MAX_STEPS","limits":{"max_steps":5,"max_tool_calls":5,"max_model_calls":5,"max_wall_time_ms":60000,"max_egress_bytes":10000,"max_model_cost_usd":1.0,"max_provider_failovers":2,"max_risk_score":0.8},"usage":{"steps":6,"tool_calls":1,"model_calls":1,"wall_time_ms":100,"egress_bytes":10,"model_cost_usd":0.1,"provider_failovers":0,"risk_score":0.1},"updated_at":"2026-02-12T10:00:00Z"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "loop", "run-abc", "--gateway-url", ts.URL}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "run-abc") || !strings.Contains(stdout.String(), "HALTED_BUDGET") {
		t.Fatalf("unexpected table output:\n%s", stdout.String())
	}
}
