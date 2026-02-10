package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
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
	code := run([]string{"status", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
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
	code := run([]string{"status", "--gateway-url", ts.URL}, strings.NewReader(""), &stdout, &stderr)
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
	code := run([]string{"status", "--gateway-url", "http://127.0.0.1:1", "--format", "table"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
}

func TestAgwResetRateLimit_AllWithoutConfirm_Fails(t *testing.T) {
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

func TestAgwResetRateLimit_PromptNo_Aborts(t *testing.T) {
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

func TestAgwResetRateLimit_PromptYes_DeletesKeys(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	spiffe := "spiffe://poc.local/agents/test/dev"
	mr.Set("ratelimit:"+spiffe+":tokens", "1.5")
	mr.Set("ratelimit:"+spiffe+":last_fill", "123")

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

func TestAgwResetRateLimit_AllConfirm_DeletesOnlyRatelimit(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	mr.Set("ratelimit:spiffe://a:tokens", "1")
	mr.Set("ratelimit:spiffe://a:last_fill", "1")
	mr.Set("session:spiffe://a", "keep")

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
