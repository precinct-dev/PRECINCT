package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/precinct-dev/precinct/internal/agw"
)

func TestAgwGDPRAudit_JSONOutput(t *testing.T) {
	orig := gdprExportDSARPackage
	t.Cleanup(func() { gdprExportDSARPackage = orig })

	gdprExportDSARPackage = func(_ctx context.Context, p agw.GDPRAuditParams) (agw.DSARExportResult, error) {
		if p.SPIFFEID != "spiffe://poc.local/agents/example/dev" {
			t.Fatalf("unexpected params: %+v", p)
		}
		return agw.DSARExportResult{
			SPIFFEID:            p.SPIFFEID,
			PackageDir:          "/tmp/reports/gdpr-dsar-example-20260211",
			SummaryPath:         "/tmp/reports/gdpr-dsar-example-20260211/dsar-summary.json",
			AuditEntriesPath:    "/tmp/reports/gdpr-dsar-example-20260211/audit-entries.jsonl",
			SessionDataPath:     "/tmp/reports/gdpr-dsar-example-20260211/session-data.json",
			RateLimitDataPath:   "/tmp/reports/gdpr-dsar-example-20260211/rate-limit-data.json",
			IdentityDetailsPath: "/tmp/reports/gdpr-dsar-example-20260211/identity-details.json",
			PolicyGrantsPath:    "/tmp/reports/gdpr-dsar-example-20260211/policy-grants.json",
		}, nil
	}

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"gdpr", "audit", "spiffe://poc.local/agents/example/dev", "--format", "json", "--keydb-url", "redis://localhost:6379"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}

	var parsed agw.DSARExportResult
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v raw=%q", err, stdout.String())
	}
	if parsed.PackageDir == "" || parsed.PolicyGrantsPath == "" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}
