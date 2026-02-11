//go:build integration
// +build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
)

func TestMakeUpgradeCheckRuns(t *testing.T) {
	cmd := exec.Command("make", "upgrade-check")
	cmd.Dir = pocDir()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make upgrade-check failed: %v\noutput:\n%s", err, string(out))
	}

	s := string(out)
	if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "CURRENT") || !strings.Contains(s, "LATEST") {
		t.Fatalf("expected table output header; got:\n%s", s)
	}
	if !strings.Contains(s, "{") || !strings.Contains(s, "\"components\"") {
		t.Fatalf("expected JSON output; got:\n%s", s)
	}
}

