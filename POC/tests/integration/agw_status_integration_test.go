//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAgwStatusIntegration_JSONAndTable(t *testing.T) {
	// AC8: Real integration against running Docker Compose stack.
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// JSON format
	{
		cmd := exec.Command("go", "run", "./cmd/agw", "status", "--gateway-url", gatewayURL, "--format", "json")
		cmd.Dir = pocDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("agw status --format json failed: %v\nOutput:\n%s", err, string(out))
		}
		var parsed struct {
			Components []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"components"`
		}
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("expected valid JSON, got err=%v output=%q", err, string(out))
		}
		if len(parsed.Components) == 0 || parsed.Components[0].Name != "gateway" {
			t.Fatalf("unexpected JSON output: %q", string(out))
		}
	}

	// Table format
	{
		cmd := exec.Command("go", "run", "./cmd/agw", "status", "--gateway-url", gatewayURL, "--format", "table")
		cmd.Dir = pocDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("agw status --format table failed: %v\nOutput:\n%s", err, string(out))
		}
		s := string(out)
		if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "gateway") {
			t.Fatalf("unexpected table output:\n%s", s)
		}
	}
}
