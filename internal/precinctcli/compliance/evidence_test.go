// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectControlEvidence_ConfigurationControl(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	out, err := CollectControlEvidence(ControlEvidenceParams{
		ControlID: "GW-AUTH-003",
		WorkDir:   wd,
	})
	if err != nil {
		t.Fatalf("CollectControlEvidence: %v", err)
	}
	if out.ControlID != "GW-AUTH-003" {
		t.Fatalf("unexpected control id: %+v", out)
	}
	if out.EvidenceType != "configuration" {
		t.Fatalf("expected configuration evidence type, got %+v", out)
	}

	payload, ok := out.Evidence.(map[string]any)
	if !ok {
		t.Fatalf("expected map evidence payload, got %T", out.Evidence)
	}
	refs, ok := payload["references"].([]string)
	if ok && len(refs) > 0 {
		if refs[0] != "spiffe-ids.yaml" {
			t.Fatalf("expected spiffe-ids.yaml reference, got %+v", refs)
		}
		return
	}
	// json/yaml decode paths may produce []any; handle that shape too.
	refsAny, ok := payload["references"].([]any)
	if !ok || len(refsAny) == 0 {
		t.Fatalf("expected references in evidence payload, got %+v", payload)
	}
	if refsAny[0] != "spiffe-ids.yaml" {
		t.Fatalf("expected spiffe-ids.yaml reference, got %+v", refsAny)
	}
}

func TestCollectControlEvidence_AuditControlFiltersEntries(t *testing.T) {
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.jsonl")
	lines := []byte(
		`{"spiffe_id":"spiffe://poc.local/agents/a/dev","action":"mcp_request"}` + "\n" +
			`{"spiffe_id":"","action":"mcp_request"}` + "\n",
	)
	if err := os.WriteFile(auditPath, lines, 0o644); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	out, err := CollectControlEvidence(ControlEvidenceParams{
		ControlID:    "GW-AUTH-001",
		AuditLogPath: auditPath,
		WorkDir:      wd,
	})
	if err != nil {
		t.Fatalf("CollectControlEvidence: %v", err)
	}
	matches, ok := out.Evidence.([]map[string]any)
	if !ok {
		t.Fatalf("expected audit evidence array, got %T", out.Evidence)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one matched audit entry, got %+v", matches)
	}
}
