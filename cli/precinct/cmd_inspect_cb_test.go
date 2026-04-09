// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrecinctInspectCircuitBreaker_JSON_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/circuit-breakers":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"bash","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30,"last_state_change":null}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "circuit-breaker", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}

	var parsed struct {
		CircuitBreakers []struct {
			Tool  string `json:"tool"`
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v; raw=%q", err, stdout.String())
	}
	if len(parsed.CircuitBreakers) != 1 || parsed.CircuitBreakers[0].Tool != "bash" || parsed.CircuitBreakers[0].State == "" {
		t.Fatalf("unexpected parsed JSON: %+v", parsed)
	}
}

func TestPrecinctInspectCircuitBreaker_SpecificTool(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/circuit-breakers/bash":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"bash","state":"open","failures":5,"threshold":5,"reset_timeout_seconds":30,"last_state_change":"2026-02-09T10:00:00Z"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "circuit-breaker", "bash", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"tool":"bash"`) {
		t.Fatalf("unexpected JSON output: %s", stdout.String())
	}
}

func TestPrecinctInspectCircuitBreaker_Table_Default(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"circuit_breakers":[{"tool":"bash","state":"closed","failures":0,"threshold":5,"reset_timeout_seconds":30,"last_state_change":null}]}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "circuit-breaker", "--gateway-url", ts.URL}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	s := stdout.String()
	if !strings.Contains(s, "TOOL") || !strings.Contains(s, "bash") {
		t.Fatalf("unexpected table output:\n%s", s)
	}
}

func TestPrecinctInspectCircuitBreaker_Unreachable_Exit1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "circuit-breaker", "--gateway-url", "http://127.0.0.1:1", "--format", "table"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
}
