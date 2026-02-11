package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgwStatus_JSON_OK(t *testing.T) {
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
	code := run([]string{"status", "--gateway-url", ts.URL, "--format", "json"}, &stdout, &stderr)
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

func TestAgwStatus_Table_Default(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","circuit_breaker":{"state":"closed"}}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--gateway-url", ts.URL}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	s := stdout.String()
	// AC4: Table mode is default, human readable.
	if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "gateway") || !strings.Contains(s, "OK") {
		t.Fatalf("unexpected table output:\n%s", s)
	}
}

func TestAgwStatus_Unreachable_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"status", "--gateway-url", "http://127.0.0.1:1", "--format", "table"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
}

