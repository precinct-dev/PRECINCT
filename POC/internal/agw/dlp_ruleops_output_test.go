package agw

import (
	"strings"
	"testing"
)

func TestRenderDLPRulesetsOutputs(t *testing.T) {
	out := DLPRulesetsOutput{
		Status: "ok",
		Active: &DLPRuleset{
			Version:  "v2",
			Digest:   "abc",
			State:    "active",
			Approved: true,
			Signed:   true,
		},
		Rulesets: []DLPRuleset{
			{Version: "v1", Digest: "d1", State: "approved", Approved: true, Signed: true},
			{Version: "v2", Digest: "abc", State: "active", Approved: true, Signed: true},
		},
	}

	js, err := RenderDLPRulesetsJSON(out)
	if err != nil {
		t.Fatalf("RenderDLPRulesetsJSON: %v", err)
	}
	if !strings.Contains(string(js), `"version": "v2"`) {
		t.Fatalf("expected json with version field, got %s", string(js))
	}

	table, err := RenderDLPRulesetsTable(out)
	if err != nil {
		t.Fatalf("RenderDLPRulesetsTable: %v", err)
	}
	if !strings.Contains(table, "Active: v2") || !strings.Contains(table, "Rulesets:") {
		t.Fatalf("unexpected table output: %s", table)
	}
}
