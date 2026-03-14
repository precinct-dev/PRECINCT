package agw

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestDeleteGDPRSubjectData_DeletesDataAndMarksAuditEntries(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	ctx := context.Background()
	spiffeID := "spiffe://poc.local/agents/example/dev"
	otherID := "spiffe://poc.local/agents/other/dev"

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	if err := rdb.Set(ctx, "session:"+spiffeID+":sid-1", `{"RiskScore":0.10}`, 30*time.Minute).Err(); err != nil {
		t.Fatalf("seed session sid-1: %v", err)
	}
	if err := rdb.RPush(ctx, "session:"+spiffeID+":sid-1:actions", `{"tool":"read"}`).Err(); err != nil {
		t.Fatalf("seed actions sid-1: %v", err)
	}
	if err := rdb.Set(ctx, "session:"+spiffeID+":sid-2", `{"RiskScore":0.20}`, 30*time.Minute).Err(); err != nil {
		t.Fatalf("seed session sid-2: %v", err)
	}
	if err := rdb.RPush(ctx, "session:"+spiffeID+":sid-2:actions", `{"tool":"grep"}`).Err(); err != nil {
		t.Fatalf("seed actions sid-2: %v", err)
	}
	if err := rdb.Set(ctx, "ratelimit:"+spiffeID+":tokens", "5.0", 2*time.Minute).Err(); err != nil {
		t.Fatalf("seed ratelimit tokens: %v", err)
	}
	if err := rdb.Set(ctx, "ratelimit:"+spiffeID+":last_fill", "12345", 2*time.Minute).Err(); err != nil {
		t.Fatalf("seed ratelimit last_fill: %v", err)
	}
	if err := rdb.Set(ctx, "session:"+otherID+":sid-keep", `{"RiskScore":0.01}`, 30*time.Minute).Err(); err != nil {
		t.Fatalf("seed keep session: %v", err)
	}

	tmp := t.TempDir()
	auditLog := filepath.Join(tmp, "audit.jsonl")
	lines := []string{
		fmt.Sprintf(`{"timestamp":"2026-02-11T10:00:00Z","decision_id":"d-1","spiffe_id":"%s","tool":"tavily_search","result":"allowed","status_code":200}`, spiffeID),
		fmt.Sprintf(`{"timestamp":"2026-02-11T10:01:00Z","decision_id":"d-2","spiffe_id":"%s","tool":"bash","result":"denied","status_code":403}`, spiffeID),
		fmt.Sprintf(`{"timestamp":"2026-02-11T10:02:00Z","decision_id":"d-3","spiffe_id":"%s","tool":"read","result":"allowed","status_code":200}`, otherID),
	}
	if err := os.WriteFile(auditLog, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	report, err := DeleteGDPRSubjectData(ctx, GDPRDeleteParams{
		SPIFFEID:         spiffeID,
		KeyDBURL:         "redis://" + mr.Addr(),
		AuditSource:      "file",
		AuditLogPath:     auditLog,
		AuditProjectRoot: tmp,
		ReportsDir:       tmp,
		Now:              time.Date(2026, 2, 11, 11, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("DeleteGDPRSubjectData: %v", err)
	}

	if report.SPIFFEID != spiffeID {
		t.Fatalf("unexpected spiffe id: %+v", report)
	}
	if len(report.Categories) != 3 {
		t.Fatalf("expected 3 categories, got %+v", report.Categories)
	}
	categoryByName := map[string]GDPRDeleteCategory{}
	for _, c := range report.Categories {
		categoryByName[c.Category] = c
	}

	if got := categoryByName["Sessions"].ItemsDeleted; got != 2 {
		t.Fatalf("expected sessions deleted=2, got %+v", report.Categories)
	}
	if got := categoryByName["Rate Limits"].ItemsDeleted; got != 2 {
		t.Fatalf("expected rate limits deleted=2, got %+v", report.Categories)
	}
	if got := categoryByName["Audit Entries"].ItemsDeleted; got != 2 {
		t.Fatalf("expected audit entries marked=2, got %+v", report.Categories)
	}
	if !strings.Contains(categoryByName["Audit Entries"].Status, "marked_deleted") {
		t.Fatalf("expected audit status to be marked_deleted, got %+v", report.Categories)
	}
	if report.TotalItemsProcessed != 6 {
		t.Fatalf("expected total=6, got %+v", report)
	}
	if len(report.DeletionCertificate) != 64 {
		t.Fatalf("expected sha256 certificate, got %q", report.DeletionCertificate)
	}

	if _, err := os.Stat(report.AuditMarkerPath); err != nil {
		t.Fatalf("expected marker path to exist: %v", err)
	}
	f, err := os.Open(report.AuditMarkerPath)
	if err != nil {
		t.Fatalf("open marker path: %v", err)
	}
	defer func() {
		_ = f.Close()
	}()
	sc := bufio.NewScanner(f)
	markerLines := 0
	for sc.Scan() {
		markerLines++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan marker file: %v", err)
	}
	if markerLines != 2 {
		t.Fatalf("expected 2 marker lines, got %d", markerLines)
	}

	auditRaw, err := os.ReadFile(auditLog)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Count(strings.TrimSpace(string(auditRaw)), "\n")+1 != 3 {
		t.Fatalf("expected original audit entries preserved, got %q", string(auditRaw))
	}

	if mr.Exists("session:"+spiffeID+":sid-1") || mr.Exists("session:"+spiffeID+":sid-2") {
		t.Fatalf("expected subject sessions deleted")
	}
	if !mr.Exists("session:" + otherID + ":sid-keep") {
		t.Fatalf("expected other identity session to remain")
	}
	if mr.Exists("ratelimit:"+spiffeID+":tokens") || mr.Exists("ratelimit:"+spiffeID+":last_fill") {
		t.Fatalf("expected rate limit keys deleted for subject")
	}
}

func TestExportGDPRDSAR_WritesCompletePackage(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	ctx := context.Background()
	spiffeID := "spiffe://poc.local/agents/example/dev"

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Set(ctx, "session:"+spiffeID+":sid-a", `{"RiskScore":0.42,"User":"alice"}`, 45*time.Minute).Err(); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := rdb.RPush(ctx, "session:"+spiffeID+":sid-a:actions", `{"tool":"tavily_search"}`, `{"tool":"read"}`).Err(); err != nil {
		t.Fatalf("seed actions: %v", err)
	}
	if err := rdb.Set(ctx, "ratelimit:"+spiffeID+":tokens", "9.0", 3*time.Minute).Err(); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}
	if err := rdb.Set(ctx, "ratelimit:"+spiffeID+":last_fill", "987654321", 3*time.Minute).Err(); err != nil {
		t.Fatalf("seed last fill: %v", err)
	}

	tmp := t.TempDir()
	auditLog := filepath.Join(tmp, "audit.jsonl")
	auditLines := []string{
		fmt.Sprintf(`{"timestamp":"2026-02-11T10:00:00Z","decision_id":"d-1","spiffe_id":"%s","tool":"tavily_search","result":"allowed","status_code":200}`, spiffeID),
		`{"timestamp":"2026-02-11T10:00:01Z","decision_id":"d-2","spiffe_id":"spiffe://poc.local/agents/other/dev","tool":"read","result":"allowed","status_code":200}`,
	}
	if err := os.WriteFile(auditLog, []byte(strings.Join(auditLines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	opaDir := filepath.Join(tmp, "opa")
	if err := os.MkdirAll(opaDir, 0o755); err != nil {
		t.Fatalf("mkdir opa: %v", err)
	}
	if err := os.WriteFile(filepath.Join(opaDir, "tool_grants.yaml"), []byte(`tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/example/*"
    description: "Example agents"
    allowed_tools: ["tavily_search", "read"]
    max_data_classification: internal
    requires_approval_for: ["bash"]
`), 0o644); err != nil {
		t.Fatalf("write grants: %v", err)
	}
	registryPath := filepath.Join(tmp, "tool-registry.yaml")
	if err := os.WriteFile(registryPath, []byte(`tools:
  - name: "tavily_search"
    risk_level: "medium"
    requires_step_up: false
  - name: "read"
    risk_level: "low"
    requires_step_up: false
`), 0o644); err != nil {
		t.Fatalf("write registry: %v", err)
	}

	result, err := ExportGDPRDSAR(ctx, GDPRAuditParams{
		SPIFFEID:         spiffeID,
		KeyDBURL:         "redis://" + mr.Addr(),
		AuditSource:      "file",
		AuditLogPath:     auditLog,
		AuditProjectRoot: tmp,
		ReportsDir:       tmp,
		OPAPolicyDir:     opaDir,
		ToolRegistryPath: registryPath,
		SPIREReader: fakeSPIREReader{
			entries: []SPIREEntry{
				{EntryID: "e-1", SPIFFEID: spiffeID, ParentID: "spiffe://poc.local/agent/local"},
				{EntryID: "e-2", SPIFFEID: "spiffe://poc.local/agents/other/dev", ParentID: "spiffe://poc.local/agent/local"},
			},
		},
		Now: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ExportGDPRDSAR: %v", err)
	}

	for _, path := range []string{
		result.PackageDir,
		result.SummaryPath,
		result.AuditEntriesPath,
		result.SessionDataPath,
		result.RateLimitDataPath,
		result.IdentityDetailsPath,
		result.PolicyGrantsPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output file %s: %v", path, err)
		}
	}

	var sessions []DSARSessionData
	sessionRaw, err := os.ReadFile(result.SessionDataPath)
	if err != nil {
		t.Fatalf("read session data: %v", err)
	}
	if err := json.Unmarshal(sessionRaw, &sessions); err != nil {
		t.Fatalf("parse session data: %v raw=%q", err, string(sessionRaw))
	}
	if len(sessions) != 1 || sessions[0].SessionID != "sid-a" || len(sessions[0].Actions) != 2 {
		t.Fatalf("unexpected sessions payload: %+v", sessions)
	}

	var identity DSARIdentityDetails
	identityRaw, err := os.ReadFile(result.IdentityDetailsPath)
	if err != nil {
		t.Fatalf("read identity details: %v", err)
	}
	if err := json.Unmarshal(identityRaw, &identity); err != nil {
		t.Fatalf("parse identity details: %v raw=%q", err, string(identityRaw))
	}
	if len(identity.SPIREEntries) != 1 || identity.SPIREEntries[0].EntryID != "e-1" {
		t.Fatalf("unexpected identity details payload: %+v", identity)
	}

	var policy PolicyListOutput
	policyRaw, err := os.ReadFile(result.PolicyGrantsPath)
	if err != nil {
		t.Fatalf("read policy grants: %v", err)
	}
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		t.Fatalf("parse policy grants: %v raw=%q", err, string(policyRaw))
	}
	if len(policy.Grants) != 1 {
		t.Fatalf("expected one policy grant, got %+v", policy.Grants)
	}

	auditFile, err := os.Open(result.AuditEntriesPath)
	if err != nil {
		t.Fatalf("open audit entries: %v", err)
	}
	defer func() {
		_ = auditFile.Close()
	}()
	sc := bufio.NewScanner(auditFile)
	auditLineCount := 0
	for sc.Scan() {
		auditLineCount++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan audit entries: %v", err)
	}
	if auditLineCount != 1 {
		t.Fatalf("expected one matched audit entry, got %d", auditLineCount)
	}

	var summary DSARSummary
	summaryRaw, err := os.ReadFile(result.SummaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		t.Fatalf("parse summary: %v raw=%q", err, string(summaryRaw))
	}
	if summary.Counts["audit_entries"] != 1 || summary.Counts["sessions"] != 1 || summary.Counts["policy_grants"] != 1 || summary.Counts["spire_entries"] != 1 {
		t.Fatalf("unexpected summary counts: %+v", summary.Counts)
	}
}

type fakeSPIREReader struct {
	entries []SPIREEntry
	err     error
}

func (f fakeSPIREReader) ListEntries(ctx context.Context) ([]SPIREEntry, error) {
	return f.entries, f.err
}
