package controlmatrix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeSignalCatalog(t *testing.T, root, rel string) {
	t.Helper()
	catalog := map[string]any{
		"required_signal_keys": []string{
			"policy.authorization_denied",
			"availability.rate_limited",
			"prompt.injection_blocked",
		},
		"mappings": map[string][]string{
			"policy.authorization_denied": {"AML.T0102"},
		},
	}
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	writeTestFile(t, root, rel, string(raw))
}

func TestCheckRepo_PassesWithFreshArtifactsAndDomains(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.March, 1, 20, 0, 0, 0, time.UTC)

	writeSignalCatalog(t, root, "docs/security/artifacts/signal.json")
	writeTestFile(t, root, "tests/e2e/validate_security_scan_artifacts.sh", "#!/usr/bin/env bash\n")
	writeTestFile(t, root, "tests/integration/usability_test.go", "package integration\n")
	writeTestFile(t, root, "tests/integration/blindspot_test.go", "package integration\n")

	writeTestFile(t, root, "build/security-scan/latest/security-scan-manifest.json", `{"ok":true}`)
	artifactPath := filepath.Join(root, "build/security-scan/latest/security-scan-manifest.json")
	if err := os.Chtimes(artifactPath, now, now); err != nil {
		t.Fatalf("chtimes artifact: %v", err)
	}

	writeTestFile(t, root, "docs/security/artifacts/control-verification-matrix.v1.json", `{
  "schema_version": "control_verification_matrix.v1",
  "title": "test",
  "signal_catalogs": ["docs/security/artifacts/signal.json"],
  "controls": [
    {
      "id": "CTRL-SEC-001",
      "domain": "security",
      "description": "security",
      "threat_refs": ["TM-001"],
      "test_evidence": [{"path":"tests/e2e/validate_security_scan_artifacts.sh","command":"make security-scan-validate"}],
      "runtime_signals": ["policy.authorization_denied"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    },
    {
      "id": "CTRL-USAB-001",
      "domain": "usability",
      "description": "usability",
      "threat_refs": ["TM-UX-001"],
      "test_evidence": [{"path":"tests/integration/usability_test.go","command":"go test ./tests/integration -run Usability"}],
      "runtime_signals": ["availability.rate_limited"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    },
    {
      "id": "CTRL-BLIND-001",
      "domain": "blindspot",
      "description": "blindspot",
      "threat_refs": ["TM-BS-001"],
      "test_evidence": [{"path":"tests/integration/blindspot_test.go","command":"go test ./tests/integration -run Blindspot"}],
      "runtime_signals": ["prompt.injection_blocked"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    }
  ]
}`)

	result, err := CheckRepo(root, "docs/security/artifacts/control-verification-matrix.v1.json", now)
	if err != nil {
		t.Fatalf("CheckRepo error: %v", err)
	}
	if len(result.Report.Issues) != 0 {
		t.Fatalf("expected no issues, got: %+v", result.Report.Issues)
	}
	if result.Report.Summary.ControlsFailed != 0 {
		t.Fatalf("expected zero failed controls, got %d", result.Report.Summary.ControlsFailed)
	}
	if !strings.Contains(RenderMarkdown(result.Report), "Control Verification Report") {
		t.Fatalf("expected markdown report header")
	}
}

func TestCheckRepo_FailsWhenArtifactIsStale(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.March, 1, 20, 0, 0, 0, time.UTC)

	writeSignalCatalog(t, root, "docs/security/artifacts/signal.json")
	writeTestFile(t, root, "tests/e2e/validate_security_scan_artifacts.sh", "#!/usr/bin/env bash\n")
	writeTestFile(t, root, "tests/integration/usability_test.go", "package integration\n")
	writeTestFile(t, root, "tests/integration/blindspot_test.go", "package integration\n")
	writeTestFile(t, root, "build/security-scan/latest/security-scan-manifest.json", `{"ok":true}`)

	old := now.Add(-72 * time.Hour)
	artifactPath := filepath.Join(root, "build/security-scan/latest/security-scan-manifest.json")
	if err := os.Chtimes(artifactPath, old, old); err != nil {
		t.Fatalf("chtimes artifact: %v", err)
	}

	writeTestFile(t, root, "docs/security/artifacts/control-verification-matrix.v1.json", `{
  "schema_version": "control_verification_matrix.v1",
  "title": "test",
  "signal_catalogs": ["docs/security/artifacts/signal.json"],
  "controls": [
    {
      "id": "CTRL-SEC-001",
      "domain": "security",
      "description": "security",
      "threat_refs": ["TM-001"],
      "test_evidence": [{"path":"tests/e2e/validate_security_scan_artifacts.sh","command":"make security-scan-validate"}],
      "runtime_signals": ["policy.authorization_denied"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    },
    {
      "id": "CTRL-USAB-001",
      "domain": "usability",
      "description": "usability",
      "threat_refs": ["TM-UX-001"],
      "test_evidence": [{"path":"tests/integration/usability_test.go","command":"go test ./tests/integration -run Usability"}],
      "runtime_signals": ["availability.rate_limited"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    },
    {
      "id": "CTRL-BLIND-001",
      "domain": "blindspot",
      "description": "blindspot",
      "threat_refs": ["TM-BS-001"],
      "test_evidence": [{"path":"tests/integration/blindspot_test.go","command":"go test ./tests/integration -run Blindspot"}],
      "runtime_signals": ["prompt.injection_blocked"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    }
  ]
}`)

	result, err := CheckRepo(root, "docs/security/artifacts/control-verification-matrix.v1.json", now)
	if err != nil {
		t.Fatalf("CheckRepo error: %v", err)
	}

	foundStale := false
	for _, issue := range result.Report.Issues {
		if issue.Code == "artifact_stale" {
			foundStale = true
			break
		}
	}
	if !foundStale {
		t.Fatalf("expected stale artifact issue, got %+v", result.Report.Issues)
	}
}

func TestCheckRepo_FailsWhenUsabilityOrBlindspotControlsMissing(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, time.March, 1, 20, 0, 0, 0, time.UTC)

	writeSignalCatalog(t, root, "docs/security/artifacts/signal.json")
	writeTestFile(t, root, "tests/e2e/validate_security_scan_artifacts.sh", "#!/usr/bin/env bash\n")
	writeTestFile(t, root, "build/security-scan/latest/security-scan-manifest.json", `{"ok":true}`)

	writeTestFile(t, root, "docs/security/artifacts/control-verification-matrix.v1.json", `{
  "schema_version": "control_verification_matrix.v1",
  "title": "test",
  "signal_catalogs": ["docs/security/artifacts/signal.json"],
  "controls": [
    {
      "id": "CTRL-SEC-001",
      "domain": "security",
      "description": "security",
      "threat_refs": ["TM-001"],
      "test_evidence": [{"path":"tests/e2e/validate_security_scan_artifacts.sh","command":"make security-scan-validate"}],
      "runtime_signals": ["policy.authorization_denied"],
      "artifacts": [{"path":"build/security-scan/latest/security-scan-manifest.json","max_age_hours":24}]
    }
  ]
}`)

	result, err := CheckRepo(root, "docs/security/artifacts/control-verification-matrix.v1.json", now)
	if err != nil {
		t.Fatalf("CheckRepo error: %v", err)
	}

	var hasUsability, hasBlindspot bool
	for _, issue := range result.Report.Issues {
		if issue.Code == "domain_missing_usability" {
			hasUsability = true
		}
		if issue.Code == "domain_missing_blindspot" {
			hasBlindspot = true
		}
	}
	if !hasUsability || !hasBlindspot {
		t.Fatalf("expected missing domain issues, got %+v", result.Report.Issues)
	}
}
