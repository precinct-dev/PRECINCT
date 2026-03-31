package precinctcli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderJSON_Valid(t *testing.T) {
	out := StatusOutput{
		Components: []ComponentStatus{
			{
				Name:   "gateway",
				Status: "ok",
				Details: map[string]any{
					"circuit_breaker": map[string]any{"state": "closed"},
				},
			},
		},
	}
	b, err := RenderJSON(out)
	if err != nil {
		t.Fatalf("RenderJSON err: %v", err)
	}

	var parsed StatusOutput
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("expected valid JSON, got unmarshal err: %v", err)
	}
	if len(parsed.Components) != 1 || parsed.Components[0].Name != "gateway" {
		t.Fatalf("unexpected parsed output: %+v", parsed)
	}
}

func TestRenderTable_HasHeaderAndRow(t *testing.T) {
	out := StatusOutput{
		Components: []ComponentStatus{
			{Name: "gateway", Status: "ok", Details: map[string]any{"circuit_breaker": `{"state":"closed"}`}},
		},
	}
	s, err := RenderTable(out)
	if err != nil {
		t.Fatalf("RenderTable err: %v", err)
	}
	if !strings.Contains(s, "COMPONENT") || !strings.Contains(s, "gateway") {
		t.Fatalf("expected table header+row, got:\n%s", s)
	}
}
