package unit

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func pocRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve POC root: %v", err)
	}
	return abs
}

func upgradeCheckScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(pocRoot(t), "scripts", "upgrade-check.sh")
}

func runScript(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("bash", append([]string{upgradeCheckScript(t)}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\noutput:\n%s", err, string(out))
	}
	return string(out)
}

func TestUpgradeCheck_Compare(t *testing.T) {
	if got := strings.TrimSpace(runScript(t, "--_test_compare", "1.10.0", "1.9.0")); got != "gt" {
		t.Fatalf("expected 1.10.0 > 1.9.0, got: %q", got)
	}
	if got := strings.TrimSpace(runScript(t, "--_test_compare", "v0.8.0", "0.8.1")); got != "lt" {
		t.Fatalf("expected 0.8.0 < 0.8.1, got: %q", got)
	}
	if got := strings.TrimSpace(runScript(t, "--_test_compare", "2.0.0", "2.0.0")); got != "eq" {
		t.Fatalf("expected equal, got: %q", got)
	}
}

func TestUpgradeCheck_ExtractImages(t *testing.T) {
	poc := pocRoot(t)
	compose := filepath.Join(poc, "docker-compose.yml")
	out := runScript(t, "--_test_extract_images", compose)
	if !strings.Contains(out, "ghcr.io/spiffe/spire-server:1.10.0") {
		t.Fatalf("expected spire-server image in compose extraction; got:\n%s", out)
	}
	if !strings.Contains(out, "eqalpha/keydb:latest") {
		t.Fatalf("expected keydb image in compose extraction; got:\n%s", out)
	}

	phoenixCompose := filepath.Join(poc, "docker-compose.phoenix.yml")
	out2 := runScript(t, "--_test_extract_images", phoenixCompose)
	if !strings.Contains(out2, "arizephoenix/phoenix:latest") {
		t.Fatalf("expected phoenix image in phoenix compose extraction; got:\n%s", out2)
	}
	if !strings.Contains(out2, "otel/opentelemetry-collector-contrib:latest") {
		t.Fatalf("expected otel-collector image in phoenix compose extraction; got:\n%s", out2)
	}
}

