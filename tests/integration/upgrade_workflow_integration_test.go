//go:build integration
// +build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustRun(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\nerr: %v\noutput:\n%s", name, strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func writeFile(t *testing.T, path string, mode os.FileMode, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}
	writeFile(t, dst, mode, string(b))
}

func createTempUpgradeRepo(t *testing.T, demoComposeExit int) string {
	t.Helper()
	tmp := t.TempDir()

	// Ignore runtime upgrade artifacts so a successful upgrade commit does not bloat history.
	writeFile(t, filepath.Join(tmp, ".gitignore"), 0o644, "config/versions.yaml.snapshot.*\nconfig/upgrade-snapshots/\n")

	writeFile(t, filepath.Join(tmp, "config", "versions.yaml"), 0o644, `components:
  keydb:
    image: eqalpha/keydb
    version: "1.0.0"
    pinned: false
`)

	// Stub upgrade-check: return deterministic JSON with an update available.
	writeFile(t, filepath.Join(tmp, "scripts", "upgrade-check.sh"), 0o755, `#!/usr/bin/env bash
set -euo pipefail
fmt="table"
if [[ "${1:-}" == "--format" ]]; then
  fmt="${2:-}"
  shift 2
fi
if [[ "$fmt" != "json" ]]; then
  echo "only json supported in test stub" >&2
  exit 2
fi
cat <<'JSON'
{"generated_at":"2026-02-11T00:00:00Z","components":[{"component":"keydb","current":"1.0.0","latest":"1.0.1","status":"UPDATE AVAILABLE","pinned":false,"image":"eqalpha/keydb"}]}
JSON
`)

	// Copy the real upgrade.sh into the temp repo.
	copyFile(t, filepath.Join(pocDir(), "scripts", "upgrade.sh"), filepath.Join(tmp, "scripts", "upgrade.sh"), 0o755)

	demoCmd := "true"
	if demoComposeExit != 0 {
		demoCmd = "false"
	}

	writeFile(t, filepath.Join(tmp, "Makefile"), 0o644, "ci:\n\t@echo \"ci pass\"\n\ndemo-compose:\n\t@"+demoCmd+"\n")

	mustRun(t, tmp, "git", "init")
	mustRun(t, tmp, "git", "config", "user.email", "test@example.com")
	mustRun(t, tmp, "git", "config", "user.name", "Test User")
	mustRun(t, tmp, "git", "add", "-A")
	mustRun(t, tmp, "git", "commit", "-m", "baseline")

	return tmp
}

func TestUpgradeWorkflow_Success(t *testing.T) {
	repo := createTempUpgradeRepo(t, 0)

	cmd := exec.Command("bash", "scripts/upgrade.sh", "--component", "keydb", "--verify")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "UPGRADE_SKIP_DOCKER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("upgrade.sh failed: %v\noutput:\n%s", err, string(out))
	}

	// Snapshot created
	snaps, _ := filepath.Glob(filepath.Join(repo, "config", "versions.yaml.snapshot.*"))
	if len(snaps) == 0 {
		t.Fatalf("expected snapshot file config/versions.yaml.snapshot.<ts> to exist")
	}

	// Versions updated
	b, err := os.ReadFile(filepath.Join(repo, "config", "versions.yaml"))
	if err != nil {
		t.Fatalf("read versions.yaml: %v", err)
	}
	if !strings.Contains(string(b), `version: "1.0.1"`) {
		t.Fatalf("expected versions.yaml to be updated; got:\n%s", string(b))
	}

	// Report created
	report := filepath.Join(repo, "docs", "upgrades", time.Now().Format("2006-01-02")+"-upgrade-report.md")
	rb, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("expected report to exist at %s: %v", report, err)
	}
	if !strings.Contains(string(rb), "Status: SUCCESS") {
		t.Fatalf("expected report status SUCCESS; got:\n%s", string(rb))
	}
	if !strings.Contains(string(rb), "- make ci: PASS") || !strings.Contains(string(rb), "- make demo-compose: PASS") {
		t.Fatalf("expected report to record PASS for both make ci and make demo-compose; got:\n%s", string(rb))
	}

	// Commit created by upgrade (baseline + upgrade)
	count := strings.TrimSpace(mustRun(t, repo, "git", "rev-list", "--count", "HEAD"))
	if count != "2" {
		t.Fatalf("expected 2 commits (baseline + upgrade), got: %s", count)
	}

	// Snapshot/log artifacts must NOT be committed.
	tree := mustRun(t, repo, "git", "ls-tree", "-r", "HEAD", "--name-only")
	if strings.Contains(tree, "config/versions.yaml.snapshot.") {
		t.Fatalf("snapshot file should be ignored and not committed; tree contains snapshot:\n%s", tree)
	}
	if strings.Contains(tree, "config/upgrade-snapshots/") {
		t.Fatalf("snapshot dir should be ignored and not committed; tree contains upgrade-snapshots:\n%s", tree)
	}
	if !strings.Contains(tree, "docs/upgrades/"+time.Now().Format("2006-01-02")+"-upgrade-report.md") {
		t.Fatalf("expected upgrade report to be committed; tree:\n%s", tree)
	}
}

func TestUpgradeWorkflow_Rollback(t *testing.T) {
	repo := createTempUpgradeRepo(t, 1)

	cmd := exec.Command("bash", "scripts/upgrade.sh", "--component", "keydb", "--verify")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "UPGRADE_SKIP_DOCKER=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected upgrade.sh to fail for rollback scenario; output:\n%s", string(out))
	}

	// Versions restored to original
	b, err := os.ReadFile(filepath.Join(repo, "config", "versions.yaml"))
	if err != nil {
		t.Fatalf("read versions.yaml: %v", err)
	}
	if !strings.Contains(string(b), `version: "1.0.0"`) {
		t.Fatalf("expected versions.yaml to be restored; got:\n%s", string(b))
	}

	// Failure report created
	report := filepath.Join(repo, "docs", "upgrades", time.Now().Format("2006-01-02")+"-upgrade-report.md")
	rb, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("expected report to exist at %s: %v", report, err)
	}
	if !strings.Contains(string(rb), "Status: FAILURE") {
		t.Fatalf("expected report status FAILURE; got:\n%s", string(rb))
	}
	if !strings.Contains(string(rb), "- make ci: PASS") || !strings.Contains(string(rb), "- make demo-compose: FAIL") {
		t.Fatalf("expected report to record PASS for ci and FAIL for demo-compose; got:\n%s", string(rb))
	}
}
