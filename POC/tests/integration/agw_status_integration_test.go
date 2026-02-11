//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAgwStatusIntegration_JSONAndTable(t *testing.T) {
	// AC9: Real integration against running Docker Compose stack.
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	// JSON format
	{
		cmd := exec.Command("go", "run", "./cmd/agw", "status", "--gateway-url", gatewayURL, "--format", "json")
		cmd.Dir = pocDir()
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		out := stdout.Bytes()
		var parsed struct {
			Components []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"components"`
		}
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("expected valid JSON on stdout, got err=%v stdout=%q stderr=%q runErr=%v", err, stdout.String(), stderr.String(), runErr)
		}
		if len(parsed.Components) != 6 {
			t.Fatalf("expected 6 components, got %d stdout=%q stderr=%q", len(parsed.Components), stdout.String(), stderr.String())
		}
		names := make([]string, 0, len(parsed.Components))
		for _, c := range parsed.Components {
			names = append(names, c.Name)
		}
		sort.Strings(names)
		want := []string{"gateway", "keydb", "otel-collector", "phoenix", "spike-nexus", "spire-server"}
		sort.Strings(want)
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Fatalf("unexpected components: got=%v want=%v", names, want)
		}

		// AC5: exit code 1 if any component is not OK.
		allOK := true
		for _, c := range parsed.Components {
			if strings.ToLower(strings.TrimSpace(c.Status)) != "ok" {
				allOK = false
				break
			}
		}
		if allOK && runErr != nil {
			t.Fatalf("expected exit 0 when all components OK, got err=%v stdout=%q stderr=%q", runErr, stdout.String(), stderr.String())
		}
		if !allOK && runErr == nil {
			t.Fatalf("expected non-zero exit when a component is not OK, got exit 0 stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		if len(parsed.Components) == 0 || parsed.Components[0].Name == "" {
			t.Fatalf("unexpected JSON output: %q", stdout.String())
		}
	}

	// Table format
	{
		cmd := exec.Command("go", "run", "./cmd/agw", "status", "--gateway-url", gatewayURL, "--format", "table")
		cmd.Dir = pocDir()
		out, err := cmd.CombinedOutput()
		s := string(out)
		if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "gateway") || !strings.Contains(s, "keydb") {
			t.Fatalf("unexpected table output:\n%s", s)
		}
		// Exit code behavior depends on whether all components are OK; asserted above for JSON output.
		_ = err
	}

	// --component gateway: detailed gateway view should include circuit breaker state.
	{
		cmd := exec.Command("go", "run", "./cmd/agw", "status", "--component", "gateway", "--gateway-url", gatewayURL, "--format", "json")
		cmd.Dir = pocDir()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("agw status --component gateway failed: %v\nOutput:\n%s", err, string(out))
		}
		var parsed struct {
			Components []struct {
				Name    string         `json:"name"`
				Status  string         `json:"status"`
				Details map[string]any `json:"details"`
			} `json:"components"`
		}
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Fatalf("invalid JSON output: %v; raw=%q", err, string(out))
		}
		if len(parsed.Components) != 1 || parsed.Components[0].Name != "gateway" {
			t.Fatalf("unexpected parsed output: %q", string(out))
		}
		if _, ok := parsed.Components[0].Details["circuit_breaker_state"]; !ok {
			t.Fatalf("expected circuit_breaker_state in details, got: %+v", parsed.Components[0].Details)
		}
	}
}
