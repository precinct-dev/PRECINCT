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

func TestPrecinctResetCircuitBreaker_AllWithoutConfirm_Fails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "circuit-breaker", "--all"},
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

func TestPrecinctResetCircuitBreaker_PromptNo_Aborts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "circuit-breaker", "bash"},
		strings.NewReader("\n"),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "aborted") {
		t.Fatalf("expected aborted error, got %q", stderr.String())
	}
}

func TestPrecinctResetCircuitBreaker_PromptYes_Table(t *testing.T) {
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
			_, _ = w.Write([]byte(`{"error":"bad request"}`))
			return
		}
		gotTool = body.Tool
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reset":[{"tool":"bash","previous_state":"open","new_state":"closed"}]}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "circuit-breaker", "bash", "--gateway-url", ts.URL},
		strings.NewReader("y\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if gotTool != "bash" {
		t.Fatalf("expected request tool=bash, got %q", gotTool)
	}
	s := stdout.String()
	if !strings.Contains(s, "TOOL") || !strings.Contains(s, "PREVIOUS_STATE") || !strings.Contains(s, "NEW_STATE") {
		t.Fatalf("unexpected table output: %q", s)
	}
	if !strings.Contains(s, "bash") || !strings.Contains(s, "open") || !strings.Contains(s, "closed") {
		t.Fatalf("expected tool transition in output, got %q", s)
	}
}

func TestPrecinctResetCircuitBreaker_AllConfirm_JSON(t *testing.T) {
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
			_, _ = w.Write([]byte(`{"error":"bad request"}`))
			return
		}
		gotTool = body.Tool
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reset":[{"tool":"read","previous_state":"open","new_state":"closed"},{"tool":"bash","previous_state":"open","new_state":"closed"}]}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "circuit-breaker", "--all", "--confirm", "--gateway-url", ts.URL, "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if gotTool != "*" {
		t.Fatalf("expected request tool='*', got %q", gotTool)
	}

	var parsed struct {
		Reset []struct {
			Tool          string `json:"tool"`
			PreviousState string `json:"previous_state"`
			NewState      string `json:"new_state"`
		} `json:"reset"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid json output, got err=%v raw=%q", err, stdout.String())
	}
	if len(parsed.Reset) != 2 {
		t.Fatalf("expected 2 reset entries, got %+v", parsed.Reset)
	}
}
