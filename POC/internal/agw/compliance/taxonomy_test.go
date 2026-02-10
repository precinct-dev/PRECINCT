package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTaxonomyAndFilterByFramework(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "taxonomy.yaml")

	yaml := `
controls:
  - id: GW-ONE
    name: One
    frameworks:
      soc2: ["CC6.1"]
    evidence_type: audit_log
    evidence_query: '.action == "mcp_request"'
  - id: GW-TWO
    name: Two
    frameworks:
      iso27001: ["A.9.2.1"]
    evidence_type: configuration
    evidence_query: null
`
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tax, err := LoadTaxonomy(p)
	if err != nil {
		t.Fatalf("LoadTaxonomy: %v", err)
	}
	if len(tax.Controls) != 2 {
		t.Fatalf("expected 2 controls, got %d", len(tax.Controls))
	}

	soc2 := FilterControlsByFramework(tax.Controls, "soc2")
	if len(soc2) != 1 || soc2[0].ID != "GW-ONE" {
		t.Fatalf("unexpected soc2 filter result: %+v", soc2)
	}
}

