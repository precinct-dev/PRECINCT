// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

var ErrNoMatchingGrants = errors.New("no matching grants for spiffe id")

type identityGrantsFile struct {
	ToolGrants []identityGrant `yaml:"tool_grants"`
}

type identityGrant struct {
	SpiffePattern         string   `yaml:"spiffe_pattern"`
	Description           string   `yaml:"description"`
	AllowedTools          []string `yaml:"allowed_tools"`
	MaxDataClassification string   `yaml:"max_data_classification"`
	RequiresApprovalFor   []string `yaml:"requires_approval_for"`
}

type identityRegistryFile struct {
	Tools []identityRegistryTool `yaml:"tools"`
}

type identityRegistryTool struct {
	Name           string `yaml:"name"`
	Hash           string `yaml:"hash"`
	RiskLevel      string `yaml:"risk_level"`
	RequiresStepUp bool   `yaml:"requires_step_up"`
}

type MatchedGrant struct {
	SPIFFEPattern         string   `json:"spiffe_pattern"`
	Description           string   `json:"description"`
	AllowedTools          []string `json:"allowed_tools"`
	MaxDataClassification string   `json:"max_data_classification"`
	RequiresApprovalFor   []string `json:"requires_approval_for"`
}

type IdentityToolPermission struct {
	Tool             string `json:"tool"`
	Authorized       bool   `json:"authorized"`
	RiskLevel        string `json:"risk_level"`
	RequiresStepUp   bool   `json:"requires_step_up"`
	ApprovalRequired bool   `json:"approval_required"`
}

type IdentityInspection struct {
	SPIFFEID      string                   `json:"spiffe_id"`
	MatchedGrants []MatchedGrant           `json:"matched_grants"`
	Tools         []IdentityToolPermission `json:"tools"`
}

func InspectIdentity(spiffeID, opaPolicyDir, toolRegistryPath string) (*IdentityInspection, error) {
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return nil, fmt.Errorf("spiffe id is empty")
	}

	grantsPath := strings.TrimRight(opaPolicyDir, "/") + "/tool_grants.yaml"
	grants, err := loadIdentityGrants(grantsPath)
	if err != nil {
		return nil, err
	}

	tools, err := loadIdentityTools(toolRegistryPath)
	if err != nil {
		return nil, err
	}

	matched := matchGrants(grants, spiffeID)
	if len(matched) == 0 {
		return nil, ErrNoMatchingGrants
	}

	inspection := &IdentityInspection{
		SPIFFEID:      spiffeID,
		MatchedGrants: make([]MatchedGrant, 0, len(matched)),
		Tools:         make([]IdentityToolPermission, 0, len(tools)),
	}

	for _, g := range matched {
		inspection.MatchedGrants = append(inspection.MatchedGrants, MatchedGrant{
			SPIFFEPattern:         g.SpiffePattern,
			Description:           g.Description,
			AllowedTools:          append([]string(nil), g.AllowedTools...),
			MaxDataClassification: g.MaxDataClassification,
			RequiresApprovalFor:   append([]string(nil), g.RequiresApprovalFor...),
		})
	}

	sort.Slice(inspection.MatchedGrants, func(i, j int) bool {
		return inspection.MatchedGrants[i].SPIFFEPattern < inspection.MatchedGrants[j].SPIFFEPattern
	})

	for _, t := range tools {
		inspection.Tools = append(inspection.Tools, IdentityToolPermission{
			Tool:             t.Name,
			Authorized:       isToolAuthorized(t.Name, matched),
			RiskLevel:        t.RiskLevel,
			RequiresStepUp:   t.RequiresStepUp,
			ApprovalRequired: requiresApproval(t.Name, matched),
		})
	}

	sort.Slice(inspection.Tools, func(i, j int) bool {
		return inspection.Tools[i].Tool < inspection.Tools[j].Tool
	})

	return inspection, nil
}

func RenderIdentityJSON(out IdentityInspection) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderIdentityTable(out IdentityInspection) (string, error) {
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "SPIFFE ID: %s\n", out.SPIFFEID)
	_, _ = fmt.Fprintln(&buf, "MATCHED GRANTS:")
	for _, g := range out.MatchedGrants {
		_, _ = fmt.Fprintf(&buf, "- %s (pattern: %s)\n", g.Description, g.SPIFFEPattern)
	}
	_, _ = fmt.Fprintln(&buf, "")

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tAUTHORIZED\tRISK_LEVEL\tSTEP_UP\tAPPROVAL")
	for _, t := range out.Tools {
		_, _ = fmt.Fprintf(
			tw,
			"%s\t%s\t%s\t%s\t%s\n",
			t.Tool,
			boolYesNo(t.Authorized),
			emptyOrValue(t.RiskLevel, "unknown"),
			boolYesNo(t.RequiresStepUp),
			boolYesNo(t.ApprovalRequired),
		)
	}
	_ = tw.Flush()
	return buf.String(), nil
}

func loadIdentityGrants(path string) ([]identityGrant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read grants file %s: %w", path, err)
	}

	var f identityGrantsFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse grants YAML %s: %w", path, err)
	}
	if len(f.ToolGrants) == 0 {
		return nil, fmt.Errorf("no tool_grants found in %s", path)
	}
	return f.ToolGrants, nil
}

func loadIdentityTools(path string) ([]identityRegistryTool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tool registry %s: %w", path, err)
	}

	var f identityRegistryFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse tool registry YAML %s: %w", path, err)
	}
	if len(f.Tools) == 0 {
		return nil, fmt.Errorf("no tools found in %s", path)
	}
	return f.Tools, nil
}

func matchGrants(grants []identityGrant, spiffeID string) []identityGrant {
	out := make([]identityGrant, 0, len(grants))
	for _, g := range grants {
		if wildcardMatch(g.SpiffePattern, spiffeID) {
			out = append(out, g)
		}
	}
	return out
}

func wildcardMatch(pattern, value string) bool {
	if strings.TrimSpace(pattern) == "" {
		return false
	}
	re := "^" + regexp.QuoteMeta(pattern) + "$"
	re = strings.ReplaceAll(re, "\\*", ".*")
	matched, err := regexp.MatchString(re, value)
	if err != nil {
		return false
	}
	return matched
}

func isToolAuthorized(tool string, grants []identityGrant) bool {
	for _, g := range grants {
		if toolInList("*", g.AllowedTools) || toolInList(tool, g.AllowedTools) {
			return true
		}
	}
	return false
}

func requiresApproval(tool string, grants []identityGrant) bool {
	for _, g := range grants {
		if toolInList(tool, g.RequiresApprovalFor) {
			return true
		}
	}
	return false
}

func toolInList(tool string, tools []string) bool {
	for _, t := range tools {
		if strings.TrimSpace(t) == tool {
			return true
		}
	}
	return false
}

func boolYesNo(v bool) string {
	if v {
		return "YES"
	}
	return "NO"
}

func emptyOrValue(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
