// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestPrecinctResetSession_AllWithoutConfirm_Fails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "session", "--all", "--keydb-url", "redis://localhost:6379"},
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

func TestPrecinctResetSession_PromptNo_Aborts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "session", "spiffe://poc.local/agents/test/dev", "--keydb-url", "redis://localhost:6379"},
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

func TestPrecinctResetSession_PromptYes_DeletesSPIFFEKeys(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	spiffe := "spiffe://poc.local/agents/test/dev"
	other := "spiffe://poc.local/agents/other/dev"
	if err := mr.Set("session:"+spiffe+":sid-1", `{"RiskScore":0.2}`); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := mr.Set("session:"+spiffe+":sid-1:actions", `[]`); err != nil {
		t.Fatalf("seed actions: %v", err)
	}
	if err := mr.Set("session:"+other+":sid-2", `{"RiskScore":0.4}`); err != nil {
		t.Fatalf("seed other session: %v", err)
	}
	if err := mr.Set("ratelimit:"+spiffe+":tokens", "1"); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}

	keydbURL := fmt.Sprintf("redis://%s", mr.Addr())

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "session", spiffe, "--keydb-url", keydbURL},
		strings.NewReader("yes\n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	if mr.Exists("session:"+spiffe+":sid-1") || mr.Exists("session:"+spiffe+":sid-1:actions") {
		t.Fatalf("expected session keys for %s deleted", spiffe)
	}
	if !mr.Exists("session:" + other + ":sid-2") {
		t.Fatalf("expected other identity session key to remain")
	}
	if !mr.Exists("ratelimit:" + spiffe + ":tokens") {
		t.Fatalf("expected non-session key to remain")
	}

	s := stdout.String()
	if !strings.Contains(s, "TARGET") || !strings.Contains(s, "DELETED") {
		t.Fatalf("unexpected table output: %q", s)
	}
	if !strings.Contains(s, spiffe) {
		t.Fatalf("expected spiffe id in output, got %q", s)
	}
}

func TestPrecinctResetSession_AllConfirm_JSON(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	if err := mr.Set("session:spiffe://a:s1", `{"RiskScore":0.1}`); err != nil {
		t.Fatalf("miniredis set session a:s1: %v", err)
	}
	if err := mr.Set("session:spiffe://a:s1:actions", `[]`); err != nil {
		t.Fatalf("miniredis set session a:s1 actions: %v", err)
	}
	if err := mr.Set("session:spiffe://b:s2", `{"RiskScore":0.2}`); err != nil {
		t.Fatalf("miniredis set session b:s2: %v", err)
	}
	if err := mr.Set("ratelimit:spiffe://a:tokens", "1"); err != nil {
		t.Fatalf("miniredis set rate limit token key: %v", err)
	}

	keydbURL := fmt.Sprintf("redis://%s", mr.Addr())

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"reset", "session", "--all", "--confirm", "--keydb-url", keydbURL, "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		Mode    string   `json:"mode"`
		Deleted int64    `json:"deleted"`
		Keys    []string `json:"keys"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid json, got err=%v raw=%q", err, stdout.String())
	}
	if parsed.Mode != "all" {
		t.Fatalf("expected mode=all, got %+v", parsed)
	}
	if parsed.Deleted != 3 {
		t.Fatalf("expected deleted=3 session keys, got %+v", parsed)
	}

	if mr.Exists("session:spiffe://a:s1") || mr.Exists("session:spiffe://a:s1:actions") || mr.Exists("session:spiffe://b:s2") {
		t.Fatalf("expected all session:* keys deleted")
	}
	if !mr.Exists("ratelimit:spiffe://a:tokens") {
		t.Fatalf("expected non-session key to remain")
	}
}
