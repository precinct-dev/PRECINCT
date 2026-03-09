package agw

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func RenderDLPRulesetsJSON(out DLPRulesetsOutput) ([]byte, error) {
	return json.MarshalIndent(out, "", "  ")
}

func RenderDLPRulesetsTable(out DLPRulesetsOutput) (string, error) {
	var b strings.Builder
	if strings.TrimSpace(out.Status) == "" {
		out.Status = "ok"
	}
	b.WriteString(fmt.Sprintf("Status: %s\n", out.Status))
	if out.Active != nil {
		b.WriteString(fmt.Sprintf("Active: %s (digest=%s state=%s)\n", out.Active.Version, out.Active.Digest, out.Active.State))
	}
	if strings.TrimSpace(out.Error) != "" {
		b.WriteString(fmt.Sprintf("Error: %s\n", out.Error))
	}
	if len(out.Rulesets) == 0 {
		return b.String(), nil
	}

	b.WriteString("Rulesets:\n")
	sort.Slice(out.Rulesets, func(i, j int) bool { return out.Rulesets[i].Version < out.Rulesets[j].Version })
	for _, rs := range out.Rulesets {
		b.WriteString(fmt.Sprintf("- %s state=%s approved=%t signed=%t digest=%s\n", rs.Version, rs.State, rs.Approved, rs.Signed, rs.Digest))
	}
	return b.String(), nil
}
