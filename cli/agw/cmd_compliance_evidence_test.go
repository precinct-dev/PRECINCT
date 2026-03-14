package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/agw/compliance"
)

func TestAgwComplianceEvidence_JSON(t *testing.T) {
	orig := complianceCollectControlEvidence
	t.Cleanup(func() { complianceCollectControlEvidence = orig })

	complianceCollectControlEvidence = func(p compliance.ControlEvidenceParams) (compliance.ControlEvidenceResult, error) {
		if p.ControlID != "GW-AUTH-001" {
			t.Fatalf("unexpected control id: %+v", p)
		}
		return compliance.ControlEvidenceResult{
			ControlID:    "GW-AUTH-001",
			Name:         "SPIFFE identity validation",
			EvidenceType: "audit_log",
			Frameworks:   []string{"SOC2", "ISO27001"},
			AuditSource:  "/tmp/audit.jsonl",
			Evidence: []map[string]any{
				{"decision_id": "d-1"},
			},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "evidence", "--control", "GW-AUTH-001", "--format", "json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed struct {
		ControlID string           `json:"control_id"`
		Evidence  []map[string]any `json:"evidence"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if parsed.ControlID != "GW-AUTH-001" || len(parsed.Evidence) != 1 {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestAgwComplianceEvidence_TableDefault(t *testing.T) {
	orig := complianceCollectControlEvidence
	t.Cleanup(func() { complianceCollectControlEvidence = orig })

	complianceCollectControlEvidence = func(p compliance.ControlEvidenceParams) (compliance.ControlEvidenceResult, error) {
		return compliance.ControlEvidenceResult{
			ControlID:    "GW-AUTH-001",
			Name:         "SPIFFE identity validation",
			EvidenceType: "configuration",
			Frameworks:   []string{"SOC2"},
			AuditSource:  "docker compose logs",
			Evidence: map[string]any{
				"references": []string{"spiffe-ids.yaml"},
			},
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "evidence", "--control", "GW-AUTH-001"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "CONTROL: GW-AUTH-001") || !strings.Contains(out, "EVIDENCE_TYPE: configuration") {
		t.Fatalf("unexpected table output: %q", out)
	}
}

func TestAgwComplianceEvidence_ControlRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "evidence"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--control is required") {
		t.Fatalf("expected control required error, got %q", stderr.String())
	}
}

func TestAgwComplianceEvidence_OpenSearchRequiresSecretMaterial(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"compliance", "evidence", "--control", "GW-AUTH-001", "--audit-source", "opensearch"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "AGW_OPENSEARCH_PASSWORD") {
		t.Fatalf("expected opensearch password env error, got %q", stderr.String())
	}
}
