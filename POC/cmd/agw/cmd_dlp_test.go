package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgwDLPUpsert_RequiresVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"dlp", "upsert"}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--version is required") {
		t.Fatalf("expected missing version error, got %q", stderr.String())
	}
}

func TestAgwDLPList_JSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/admin/dlp/rulesets" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","active":{"version":"v2","digest":"abc","state":"active"},"rulesets":[{"version":"v2","digest":"abc","state":"active","approved":true,"signed":true}]}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"dlp", "list", "--gateway-url", ts.URL, "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"version": "v2"`) {
		t.Fatalf("expected json output with ruleset version, got %q", stdout.String())
	}
}

func TestAgwDLPPromote_FailureSurfaced(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/dlp/rulesets/v2/promote" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"failed","error":"ruleset v2 is not approved/signed"}`))
	}))
	t.Cleanup(ts.Close)

	var stdout, stderr bytes.Buffer
	code := run([]string{"dlp", "promote", "--version", "v2", "--gateway-url", ts.URL}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "not approved/signed") {
		t.Fatalf("expected promote failure reason, got %q", stderr.String())
	}
}
