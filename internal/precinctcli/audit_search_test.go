// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseAuditWindow(t *testing.T) {
	t.Run("duration_units", func(t *testing.T) {
		got, err := ParseAuditWindow("24h")
		if err != nil {
			t.Fatalf("ParseAuditWindow: %v", err)
		}
		if got != 24*time.Hour {
			t.Fatalf("expected 24h, got %v", got)
		}
	})

	t.Run("day_suffix", func(t *testing.T) {
		got, err := ParseAuditWindow("7d")
		if err != nil {
			t.Fatalf("ParseAuditWindow: %v", err)
		}
		if got != 7*24*time.Hour {
			t.Fatalf("expected 168h, got %v", got)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		if _, err := ParseAuditWindow("bad"); err == nil {
			t.Fatal("expected error for invalid window")
		}
	})
}

func TestFilterAuditEntries(t *testing.T) {
	now := time.Date(2026, time.February, 11, 10, 0, 0, 0, time.UTC)
	entries := []map[string]any{
		{
			"timestamp":   now.Add(-30 * time.Minute).Format(time.RFC3339),
			"decision_id": "d-allow-recent",
			"spiffe_id":   "spiffe://poc.local/agents/a/dev",
			"tool":        "tavily_search",
			"result":      "allowed",
			"status_code": 200,
		},
		{
			"timestamp":   now.Add(-2 * time.Hour).Format(time.RFC3339),
			"decision_id": "d-denied-recent",
			"spiffe_id":   "spiffe://poc.local/agents/a/dev",
			"tool":        "bash",
			"result":      "denied",
			"status_code": 403,
		},
		{
			"timestamp":   now.Add(-8 * 24 * time.Hour).Format(time.RFC3339),
			"decision_id": "d-denied-old",
			"spiffe_id":   "spiffe://poc.local/agents/b/dev",
			"tool":        "read",
			"result":      "denied",
			"status_code": 403,
		},
	}

	t.Run("decision_id", func(t *testing.T) {
		got, err := FilterAuditEntries(entries, AuditSearchFilter{
			DecisionID: "d-denied-recent",
			Now:        now,
		})
		if err != nil {
			t.Fatalf("FilterAuditEntries: %v", err)
		}
		if len(got) != 1 || got[0]["decision_id"] != "d-denied-recent" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("spiffe_and_time", func(t *testing.T) {
		got, err := FilterAuditEntries(entries, AuditSearchFilter{
			SPIFFEID: "spiffe://poc.local/agents/a/dev",
			Last:     "1h",
			Now:      now,
		})
		if err != nil {
			t.Fatalf("FilterAuditEntries: %v", err)
		}
		if len(got) != 1 || got[0]["decision_id"] != "d-allow-recent" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("denied_and_time", func(t *testing.T) {
		got, err := FilterAuditEntries(entries, AuditSearchFilter{
			DeniedOnly: true,
			Last:       "7d",
			Now:        now,
		})
		if err != nil {
			t.Fatalf("FilterAuditEntries: %v", err)
		}
		if len(got) != 1 || got[0]["decision_id"] != "d-denied-recent" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})

	t.Run("tool", func(t *testing.T) {
		got, err := FilterAuditEntries(entries, AuditSearchFilter{
			Tool: "bash",
			Now:  now,
		})
		if err != nil {
			t.Fatalf("FilterAuditEntries: %v", err)
		}
		if len(got) != 1 || got[0]["tool"] != "bash" {
			t.Fatalf("unexpected result: %+v", got)
		}
	})
}

func TestRenderAuditSearchJSON(t *testing.T) {
	entries := []map[string]any{
		{
			"decision_id": "d1",
			"result":      "allowed",
		},
	}
	b, err := RenderAuditSearchJSON(entries)
	if err != nil {
		t.Fatalf("RenderAuditSearchJSON: %v", err)
	}

	var parsed []map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("invalid json: %v output=%q", err, string(b))
	}
	if len(parsed) != 1 || parsed[0]["decision_id"] != "d1" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}
