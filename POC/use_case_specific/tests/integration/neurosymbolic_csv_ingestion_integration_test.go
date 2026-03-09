package integration

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	nsadapter "github.com/example/agentic-security-poc/internal/integrations/neurosymbolic"
)

func TestNeuroSymbolicCSVIngestion_ContextAdmissionAllowAndDeny(t *testing.T) {
	baseURL := newRuleOpsTestServerURL(t)
	spiffeID := "spiffe://poc.local/agents/mcp-client/dspy-reasoner/dev"
	sessionID := fmt.Sprintf("neurosymbolic-csv-it-%d", time.Now().UnixNano())

	policy := nsadapter.CSVPolicy{
		MaxBytes:        8 * 1024,
		RequiredHeaders: []string{"fact_id", "subject", "predicate", "object"},
	}
	envelope := nsadapter.EnvelopeParams{
		RunID:     "ns-csv-it-allow",
		SessionID: sessionID,
		SPIFFEID:  spiffeID,
		Plane:     "context",
	}
	opts := nsadapter.AdmissionOptions{
		ModelEgress:       true,
		MemoryOperation:   "write",
		DLPClassification: "clean",
	}

	safeCSV := []byte("fact_id,subject,predicate,object,confidence\nf1,bioactive-a,interacts,bioactive-b,0.92\nf2,bioactive-c,inhibits,bioactive-d,0.86\n")
	allowReq, allowReport, err := nsadapter.BuildContextAdmissionRequestFromCSV(
		safeCSV,
		"upload://facts/safe.csv",
		policy,
		envelope,
		opts,
	)
	if err != nil {
		t.Fatalf("build safe request: %v", err)
	}
	if !allowReport.SchemaValid || allowReport.MaliciousContentDetected {
		t.Fatalf("unexpected safe report %+v", allowReport)
	}

	code, body := ruleOpsPostAs(t, baseURL+"/v1/context/admit", allowReq, spiffeID)
	if code != http.StatusOK {
		t.Fatalf("safe CSV expected 200, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_ALLOW" {
		t.Fatalf("safe CSV expected CONTEXT_ALLOW, got %q body=%v", reason, body)
	}
	metadata, _ := body["metadata"].(map[string]any)
	if stringField(metadata["ingestion_profile"]) != "neuro_symbolic_csv" {
		t.Fatalf("safe CSV expected ingestion_profile metadata, got %v", metadata)
	}

	maliciousCSV := []byte("fact_id,subject,predicate,object\nf1,bioactive-a,interacts,=cmd|' /C calc'!A0\n")
	denyReq, denyReport, err := nsadapter.BuildContextAdmissionRequestFromCSV(
		maliciousCSV,
		"upload://facts/malicious.csv",
		policy,
		nsadapter.EnvelopeParams{
			RunID:     "ns-csv-it-deny-validation",
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "context",
		},
		opts,
	)
	if err != nil {
		t.Fatalf("build malicious request: %v", err)
	}
	if !denyReport.MaliciousContentDetected {
		t.Fatalf("expected malicious fixture to trigger report detection %+v", denyReport)
	}

	code, body = ruleOpsPostAs(t, baseURL+"/v1/context/admit", denyReq, spiffeID)
	if code != http.StatusForbidden {
		t.Fatalf("malicious CSV expected 403, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_FACTS_CSV_VALIDATION_FAILED" {
		t.Fatalf("malicious CSV expected CONTEXT_FACTS_CSV_VALIDATION_FAILED, got %q body=%v", reason, body)
	}

	tamperReq, _, err := nsadapter.BuildContextAdmissionRequestFromCSV(
		safeCSV,
		"upload://facts/tampered.csv",
		policy,
		nsadapter.EnvelopeParams{
			RunID:     "ns-csv-it-deny-provenance",
			SessionID: sessionID,
			SPIFFEID:  spiffeID,
			Plane:     "context",
		},
		opts,
	)
	if err != nil {
		t.Fatalf("build tampered request: %v", err)
	}
	policyBody := mapFieldStrict(t, tamperReq["policy"])
	attrs := mapFieldStrict(t, policyBody["attributes"])
	attrs["facts_hash"] = "sha256:deadbeef"
	provenance := mapFieldStrict(t, attrs["provenance"])
	provenance["checksum"] = "sha256:feedface"
	attrs["facts_hash_verified"] = true
	provenance["verified"] = true

	code, body = ruleOpsPostAs(t, baseURL+"/v1/context/admit", tamperReq, spiffeID)
	if code != http.StatusForbidden {
		t.Fatalf("tampered CSV expected 403, got %d body=%v", code, body)
	}
	if reason := stringField(body["reason_code"]); reason != "CONTEXT_FACTS_PROVENANCE_INVALID" {
		t.Fatalf("tampered CSV expected CONTEXT_FACTS_PROVENANCE_INVALID, got %q body=%v", reason, body)
	}
}

func mapFieldStrict(t *testing.T, v any) map[string]any {
	t.Helper()
	out, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	return out
}
