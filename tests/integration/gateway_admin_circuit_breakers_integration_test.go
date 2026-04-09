// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestGatewayAdminCircuitBreakersIntegration_NonEmpty(t *testing.T) {
	// This is an integration test: it must run against a live gateway.
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, gatewayURL+"/admin/circuit-breakers", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-SPIFFE-ID", adminSPIFFEIDForTest())
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/circuit-breakers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status=%d", resp.StatusCode)
	}

	var parsed struct {
		CircuitBreakers []struct {
			Tool  string `json:"tool"`
			State string `json:"state"`
		} `json:"circuit_breakers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(parsed.CircuitBreakers) == 0 {
		t.Fatalf("expected non-empty circuit_breakers array, got %+v", parsed)
	}
	for _, e := range parsed.CircuitBreakers {
		if e.Tool == "" || e.State == "" {
			t.Fatalf("expected tool+state populated, got %+v", e)
		}
	}
}
