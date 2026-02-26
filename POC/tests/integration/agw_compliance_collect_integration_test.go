//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RamXX/agentic_reference_architecture/POC/internal/agw/compliance"
)

func TestAgwComplianceCollect_SOC2EvidencePackage(t *testing.T) {
	if err := waitForService(gatewayURL+"/health", 30*time.Second); err != nil {
		t.Fatalf("Gateway not ready: %v", err)
	}

	projectRoot := pocDir()
	outBase := t.TempDir()

	cmd := exec.Command(
		"go", "run", "./cmd/agw",
		"compliance", "collect",
		"--framework", "soc2",
		"--gateway-url", gatewayURL,
		"--output-dir", outBase,
	)
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("agw compliance collect failed: %v\nOutput:\n%s", err, string(out))
	}

	evidenceDir := strings.TrimSpace(string(out))
	if evidenceDir == "" {
		t.Fatalf("expected evidence dir in stdout, got empty output")
	}

	frameworkDir := filepath.Join(evidenceDir, "soc2")
	summaryPath := filepath.Join(frameworkDir, "evidence-summary.json")
	auditSnap := filepath.Join(frameworkDir, "audit-log-snapshot.jsonl")
	if err := exec.Command("test", "-f", summaryPath).Run(); err != nil {
		t.Fatalf("missing evidence summary at %s", summaryPath)
	}
	if err := exec.Command("test", "-f", auditSnap).Run(); err != nil {
		t.Fatalf("missing audit snapshot at %s", auditSnap)
	}

	// Summary fields.
	{
		b, err := exec.Command("cat", summaryPath).Output()
		if err != nil {
			t.Fatalf("read summary: %v", err)
		}
		var s struct {
			Framework    string `json:"framework"`
			ControlCount int    `json:"control_count"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatalf("invalid summary JSON: %v", err)
		}
		if s.Framework != "soc2" {
			t.Fatalf("expected framework=soc2, got %q", s.Framework)
		}

		// Ensure we created dirs for every SOC2 control in taxonomy.
		tax, err := compliance.LoadTaxonomy(filepath.Join(projectRoot, "tools/compliance/control_taxonomy.yaml"))
		if err != nil {
			t.Fatalf("load taxonomy: %v", err)
		}
		soc2Controls := compliance.FilterControlsByFramework(tax.Controls, "soc2")
		if s.ControlCount != len(soc2Controls) {
			t.Fatalf("expected control_count=%d, got %d", len(soc2Controls), s.ControlCount)
		}
		for _, c := range soc2Controls {
			controlDir := filepath.Join(frameworkDir, "controls", c.ID)
			if err := exec.Command("test", "-d", controlDir).Run(); err != nil {
				t.Fatalf("missing control dir %s", controlDir)
			}
		}
	}

	// Required config snapshots exist (at least the ones enumerated in story).
	for _, name := range []string{"tool-registry.yaml", "tool_grants.yaml", "risk_thresholds.yaml", "spiffe-ids.yaml"} {
		p := filepath.Join(frameworkDir, "config-snapshots", name)
		if err := exec.Command("test", "-f", p).Run(); err != nil {
			t.Fatalf("missing config snapshot %s", p)
		}
	}
}
