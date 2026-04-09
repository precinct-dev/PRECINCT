// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import "strings"

type AdminMiddlewareNames struct {
	ConnectorAuth string
	RuleOps       string
	Approval      string
	BreakGlass    string
	Profile       string
	LoopRuns      string
	Circuit       string
	PolicyReload  string
	Default       string
}

func DefaultAdminMiddlewareNames() AdminMiddlewareNames {
	return AdminMiddlewareNames{
		ConnectorAuth: "v24_connector_authority",
		RuleOps:       "v24_ruleops_admin",
		Approval:      "v24_approval_admin",
		BreakGlass:    "v24_break_glass_admin",
		Profile:       "v24_profile_admin",
		LoopRuns:      "v24_loop_admin",
		Circuit:       "v24_circuit_breaker_admin",
		PolicyReload:  "v24_policy_reload_admin",
	}
}

func ResolveAdminMiddlewareForPath(path string, names AdminMiddlewareNames) string {
	if strings.TrimSpace(path) == "" {
		return names.Default
	}
	if names.ConnectorAuth == "" {
		names.ConnectorAuth = "v24_connector_authority"
	}
	if names.RuleOps == "" {
		names.RuleOps = "v24_ruleops_admin"
	}
	if names.Approval == "" {
		names.Approval = "v24_approval_admin"
	}
	if names.BreakGlass == "" {
		names.BreakGlass = "v24_break_glass_admin"
	}
	if names.Profile == "" {
		names.Profile = "v24_profile_admin"
	}
	if names.LoopRuns == "" {
		names.LoopRuns = "v24_loop_admin"
	}
	if names.Circuit == "" {
		names.Circuit = "v24_circuit_breaker_admin"
	}
	if names.PolicyReload == "" {
		names.PolicyReload = "v24_policy_reload_admin"
	}
	if names.Default == "" {
		names.Default = "v24_admin_authz"
	}

	switch {
	case strings.HasPrefix(path, "/admin/dlp/rulesets"):
		return names.RuleOps
	case strings.HasPrefix(path, "/admin/approvals"):
		return names.Approval
	case strings.HasPrefix(path, "/admin/breakglass"):
		return names.BreakGlass
	case strings.HasPrefix(path, "/admin/profiles"):
		return names.Profile
	case strings.HasPrefix(path, "/admin/loop/runs"):
		return names.LoopRuns
	case strings.HasPrefix(path, "/admin/circuit-breakers"):
		return names.Circuit
	case strings.EqualFold(path, "/admin/policy/reload"):
		return names.PolicyReload
	default:
		if strings.EqualFold(path, "/admin") || strings.HasPrefix(path, "/admin/") {
			return names.Default
		}
		return names.Default
	}
}

func IsAdminPath(path string) bool {
	return path == "/admin" || strings.HasPrefix(path, "/admin/")
}

func NormalizeAdminAuthzAllowlist(ids []string) map[string]struct{} {
	normalized := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		normalized[id] = struct{}{}
	}
	return normalized
}

func IsAdminPrincipalAuthorized(allowed map[string]struct{}, spiffeID string) bool {
	if len(allowed) == 0 {
		return false
	}
	_, ok := allowed[strings.TrimSpace(spiffeID)]
	return ok
}
