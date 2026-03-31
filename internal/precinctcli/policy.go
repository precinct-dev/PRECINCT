package precinctcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

type PolicyGrant struct {
	Description        string   `json:"description"`
	SPIFFEPattern      string   `json:"spiffe_pattern"`
	AllowedTools       []string `json:"allowed_tools"`
	Classification     string   `json:"classification"`
	ApprovalRequired   []string `json:"approval_required"`
	RegisteredToolRefs int      `json:"registered_tool_refs"`
}

type PolicyListOutput struct {
	Grants []PolicyGrant `json:"grants"`
}

func ListPolicyGrants(opaPolicyDir, toolRegistryPath, spiffeID string) (PolicyListOutput, error) {
	grantsPath := strings.TrimRight(strings.TrimSpace(opaPolicyDir), "/") + "/tool_grants.yaml"
	grants, err := loadIdentityGrants(grantsPath)
	if err != nil {
		return PolicyListOutput{}, err
	}

	tools, err := loadIdentityTools(strings.TrimSpace(toolRegistryPath))
	if err != nil {
		return PolicyListOutput{}, err
	}
	registrySet := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		registrySet[strings.TrimSpace(tool.Name)] = struct{}{}
	}

	filter := strings.TrimSpace(spiffeID)
	out := PolicyListOutput{Grants: make([]PolicyGrant, 0, len(grants))}
	for _, g := range grants {
		if filter != "" && !wildcardMatch(g.SpiffePattern, filter) {
			continue
		}

		registeredRefs := 0
		for _, t := range g.AllowedTools {
			t = strings.TrimSpace(t)
			if t == "*" {
				registeredRefs = len(registrySet)
				break
			}
			if _, ok := registrySet[t]; ok {
				registeredRefs++
			}
		}

		grant := PolicyGrant{
			Description:        g.Description,
			SPIFFEPattern:      g.SpiffePattern,
			AllowedTools:       append([]string(nil), g.AllowedTools...),
			Classification:     g.MaxDataClassification,
			ApprovalRequired:   append([]string(nil), g.RequiresApprovalFor...),
			RegisteredToolRefs: registeredRefs,
		}
		out.Grants = append(out.Grants, grant)
	}

	sort.Slice(out.Grants, func(i, j int) bool {
		if out.Grants[i].SPIFFEPattern == out.Grants[j].SPIFFEPattern {
			return out.Grants[i].Description < out.Grants[j].Description
		}
		return out.Grants[i].SPIFFEPattern < out.Grants[j].SPIFFEPattern
	})

	return out, nil
}

func RenderPolicyListJSON(out PolicyListOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderPolicyListTable(out PolicyListOutput) (string, error) {
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "GRANT\tSPIFFE_PATTERN\tALLOWED_TOOLS\tCLASSIFICATION\tAPPROVAL_REQUIRED")
	for _, g := range out.Grants {
		tools := "-"
		if len(g.AllowedTools) > 0 {
			tools = strings.Join(g.AllowedTools, ", ")
		}
		approvals := "-"
		if len(g.ApprovalRequired) > 0 {
			approvals = strings.Join(g.ApprovalRequired, ", ")
		}
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\n",
			emptyOrValue(g.Description, "-"),
			g.SPIFFEPattern,
			tools,
			emptyOrValue(g.Classification, "-"),
			approvals,
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}
