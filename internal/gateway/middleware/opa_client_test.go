// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOPAClientHasTimeout(t *testing.T) {
	c := NewOPAClient("http://localhost:8181")
	if c.client.Timeout != 5*time.Second {
		t.Fatalf("OPA client timeout = %v, want 5s", c.client.Timeout)
	}
}

func TestOPAClientTimesOutOnSlowServer(t *testing.T) {
	// Create a test HTTP server that delays longer than the 5s timeout.
	// We use 10s sleep so the timeout fires well before the handler returns.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer slow.Close()

	c := NewOPAClient(slow.URL)

	start := time.Now()
	_, reason, err := c.Evaluate(OPAInput{
		SPIFFEID: "spiffe://test/slow",
		Tool:     "test_tool",
		Action:   "execute",
	})
	elapsed := time.Since(start)

	// The client should return without waiting for the full 10s server delay.
	// We allow up to 7s to avoid flaky test edges but expect ~5s.
	if elapsed > 7*time.Second {
		t.Fatalf("Evaluate took %v, expected timeout around 5s", elapsed)
	}

	// Evaluate returns (false, "opa_unavailable", nil) when the HTTP call fails,
	// so err should be nil (OPA fail-closed logic) and reason should indicate unavailable.
	if err != nil {
		t.Fatalf("expected nil error from fail-closed logic, got: %v", err)
	}
	if reason != "opa_unavailable" {
		t.Fatalf("expected reason 'opa_unavailable', got: %q", reason)
	}
}
