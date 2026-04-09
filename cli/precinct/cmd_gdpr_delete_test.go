// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/precinctcli"
)

func TestPrecinctGDPRDelete_RequiresConfirm(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"gdpr", "delete", "spiffe://poc.local/agents/example/dev"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--confirm is required for gdpr delete") {
		t.Fatalf("expected --confirm required error, got %q", stderr.String())
	}
}

func TestPrecinctGDPRDelete_JSONOutput(t *testing.T) {
	orig := gdprDeleteSubjectData
	t.Cleanup(func() { gdprDeleteSubjectData = orig })

	gdprDeleteSubjectData = func(_ctx context.Context, p precinctcli.GDPRDeleteParams) (precinctcli.GDPRDeleteReport, error) {
		if p.SPIFFEID != "spiffe://poc.local/agents/example/dev" {
			t.Fatalf("unexpected params: %+v", p)
		}
		return precinctcli.GDPRDeleteReport{
			SPIFFEID:  p.SPIFFEID,
			Timestamp: "2026-02-11T10:00:00Z",
			Categories: []precinctcli.GDPRDeleteCategory{
				{Category: "Sessions", ItemsDeleted: 2, Status: "deleted"},
			},
			TotalItemsProcessed: 2,
			DeletionCertificate: strings.Repeat("a", 64),
			AuditMarkerPath:     "/tmp/gdpr-audit-markers.jsonl",
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"gdpr", "delete", "spiffe://poc.local/agents/example/dev", "--confirm", "--format", "json", "--keydb-url", "redis://localhost:6379"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed precinctcli.GDPRDeleteReport
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if parsed.SPIFFEID == "" || parsed.DeletionCertificate == "" {
		t.Fatalf("unexpected parsed report: %+v", parsed)
	}
}
