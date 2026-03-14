//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAgwGDPRDeleteIntegration_CreateDeleteVerifyLifecycle(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/gdpr-delete-researcher/dev"
	keydbURL := integrationKeyDBURL()

	sessionID := "gdpr-delete-int-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	sessionKey := "session:" + spiffeID + ":" + sessionID
	actionsKey := sessionKey + ":actions"
	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	keydbSetValue(t, sessionKey, `{"RiskScore":0.33}`, 10*time.Minute)
	keydbRPushValues(t, actionsKey, `{"tool":"tavily_search"}`)
	keydbSetValue(t, tokensKey, "12.0", 10*time.Minute)
	keydbSetValue(t, lastFillKey, strconv.FormatInt(time.Now().UnixNano(), 10), 10*time.Minute)

	// Create a live audit entry for the SPIFFE identity.
	_ = postGatewayRPCMethod(t, spiffeID, "tool_does_not_exist_for_gdpr_delete_integration", map[string]any{
		"reason": "gdpr-delete-lifecycle",
	})
	time.Sleep(400 * time.Millisecond)

	outputDir := filepath.Join(t.TempDir(), "reports")
	cmd := exec.Command(
		"go", "run", "./cmd/agw", "gdpr", "delete", spiffeID,
		"--confirm",
		"--source", "docker",
		"--project-root", ".",
		"--output-dir", outputDir,
		"--keydb-url", keydbURL,
		"--format", "json",
	)
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agw gdpr delete failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var report struct {
		SPIFFEID            string `json:"spiffe_id"`
		TotalItemsProcessed int    `json:"total_items_processed"`
		DeletionCertificate string `json:"deletion_certificate"`
		AuditMarkerPath     string `json:"audit_marker_path"`
		Categories          []struct {
			Category string `json:"category"`
			Status   string `json:"status"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid gdpr delete json: %v raw=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	if report.SPIFFEID != spiffeID {
		t.Fatalf("unexpected spiffe id in report: %+v", report)
	}
	if report.TotalItemsProcessed < 3 {
		t.Fatalf("expected at least session+ratelimit deletes, got %+v", report)
	}
	if len(report.DeletionCertificate) != 64 {
		t.Fatalf("expected SHA-256 certificate, got %+v", report)
	}
	if strings.TrimSpace(report.AuditMarkerPath) == "" {
		t.Fatalf("expected audit marker path in report: %+v", report)
	}
	if _, err := os.Stat(report.AuditMarkerPath); err != nil {
		t.Fatalf("expected audit marker file at %s: %v", report.AuditMarkerPath, err)
	}

	var auditMarked bool
	for _, c := range report.Categories {
		if c.Category == "Audit Entries" && strings.Contains(c.Status, "marked_deleted") {
			auditMarked = true
		}
	}
	if !auditMarked {
		t.Fatalf("expected audit category to be marked_deleted: %+v", report.Categories)
	}

	if exists := keydbExists(t, sessionKey, actionsKey); exists != 0 {
		t.Fatalf("expected subject session keys deleted, exists=%d", exists)
	}
	if exists := keydbExists(t, tokensKey, lastFillKey); exists != 0 {
		t.Fatalf("expected subject ratelimit keys deleted, exists=%d", exists)
	}
}

func TestAgwGDPRAuditIntegration_ExportsCompleteDSARPackage(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	spiffeID := "spiffe://poc.local/agents/mcp-client/gdpr-audit-researcher/dev"
	keydbURL := integrationKeyDBURL()

	sessionID := "gdpr-audit-int-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	sessionKey := "session:" + spiffeID + ":" + sessionID
	actionsKey := sessionKey + ":actions"
	tokensKey := "ratelimit:" + spiffeID + ":tokens"
	lastFillKey := "ratelimit:" + spiffeID + ":last_fill"

	keydbSetValue(t, sessionKey, `{"RiskScore":0.27}`, 10*time.Minute)
	keydbRPushValues(t, actionsKey, `{"tool":"tavily_search"}`, `{"tool":"read"}`)
	keydbSetValue(t, tokensKey, "15.0", 10*time.Minute)
	keydbSetValue(t, lastFillKey, strconv.FormatInt(time.Now().UnixNano(), 10), 10*time.Minute)

	_ = postGatewayRPCMethod(t, spiffeID, "tavily_search", map[string]any{"query": "gdpr-audit-dsar-integration"})
	time.Sleep(400 * time.Millisecond)

	outputDir := filepath.Join(t.TempDir(), "reports")
	cmd := exec.Command(
		"go", "run", "./cmd/agw", "gdpr", "audit", spiffeID,
		"--source", "docker",
		"--project-root", ".",
		"--output-dir", outputDir,
		"--keydb-url", keydbURL,
		"--format", "json",
	)
	cmd.Dir = pocDir()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agw gdpr audit failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}

	var result struct {
		PackageDir          string `json:"package_dir"`
		SummaryPath         string `json:"summary_path"`
		AuditEntriesPath    string `json:"audit_entries_path"`
		SessionDataPath     string `json:"session_data_path"`
		RateLimitDataPath   string `json:"rate_limit_data_path"`
		IdentityDetailsPath string `json:"identity_details_path"`
		PolicyGrantsPath    string `json:"policy_grants_path"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid gdpr audit json: %v raw=%q stderr=%q", err, stdout.String(), stderr.String())
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
			t.Fatalf("expected DSAR file %s: %v", path, err)
		}
	}

	summaryRaw, err := os.ReadFile(result.SummaryPath)
	if err != nil {
		t.Fatalf("read DSAR summary: %v", err)
	}
	var summary struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(summaryRaw, &summary); err != nil {
		t.Fatalf("parse DSAR summary: %v raw=%q", err, string(summaryRaw))
	}
	if summary.Counts["sessions"] < 1 {
		t.Fatalf("expected at least one session in DSAR summary, got %+v", summary.Counts)
	}
	if summary.Counts["audit_entries"] < 1 {
		t.Fatalf("expected at least one audit entry in DSAR summary, got %+v", summary.Counts)
	}
}
