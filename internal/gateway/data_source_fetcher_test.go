// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/gateway/middleware"
)

func TestHTTPDataSourceFetcher_AllowsConfiguredHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	parsed, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	fetcher := newHTTPDataSourceFetcher(&middleware.DestinationAllowlist{
		Allowed: []string{parsed.Hostname()},
	})

	body, err := fetcher(ts.URL + "/data.json")
	if err != nil {
		t.Fatalf("expected allowlisted fetch to succeed, got error: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected fetch body: %s", string(body))
	}
}

func TestHTTPDataSourceFetcher_RejectsNonAllowlistedHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	fetcher := newHTTPDataSourceFetcher(&middleware.DestinationAllowlist{
		Allowed: []string{"example.com"},
	})

	_, err := fetcher(ts.URL + "/blocked")
	if err == nil {
		t.Fatal("expected non-allowlisted host to be rejected")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("expected allowlist rejection, got: %v", err)
	}
}

func TestHTTPDataSourceFetcher_RejectsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("target"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/payload", http.StatusFound)
	}))
	defer redirector.Close()

	parsed, err := url.Parse(redirector.URL)
	if err != nil {
		t.Fatalf("parse redirector URL: %v", err)
	}

	fetcher := newHTTPDataSourceFetcher(&middleware.DestinationAllowlist{
		Allowed: []string{parsed.Hostname()},
	})

	_, err = fetcher(redirector.URL + "/redirect")
	if err == nil {
		t.Fatal("expected redirecting data source fetch to be rejected")
	}
	if !strings.Contains(err.Error(), "redirects are not allowed") {
		t.Fatalf("expected redirect rejection, got: %v", err)
	}
}
