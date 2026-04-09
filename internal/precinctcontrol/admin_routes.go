// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcontrol

import (
	"net/http"
	"strings"
)

const (
	adminDLPRulesetsPath     = "/admin/dlp/rulesets"
	adminApprovalsPath       = "/admin/approvals"
	adminBreakGlassPath      = "/admin/breakglass"
	adminProfilesPath        = "/admin/profiles"
	adminLoopRunsPath        = "/admin/loop/runs"
	adminCircuitBreakersPath = "/admin/circuit-breakers"
	adminPolicyReloadPath    = "/admin/policy/reload"
)

type AdminGatewayRoutes struct {
	HandleDLPRulesets    func(http.ResponseWriter, *http.Request) bool
	HandleApprovals      func(http.ResponseWriter, *http.Request) bool
	HandleBreakGlass     func(http.ResponseWriter, *http.Request) bool
	HandleProfiles       func(http.ResponseWriter, *http.Request) bool
	HandleLoopRuns       func(http.ResponseWriter, *http.Request) bool
	HandleCircuitBreaker func(http.ResponseWriter, *http.Request) bool
	HandlePolicyReload   func(http.ResponseWriter, *http.Request) bool
	HandleFallback       func(http.ResponseWriter, *http.Request) bool
}

type AdminRouteConfig struct {
	MiddlewareStep int
	RuleOps        string
	Approval       string
	BreakGlass     string
	Profile        string
	LoopRuns       string
	Circuit        string
	PolicyReload   string
	Default        string
}

func BuildAdminRoutes(cfg AdminRouteConfig, routes AdminGatewayRoutes) []ControlRoute {
	ruleOps := strings.TrimSpace(cfg.RuleOps)
	if ruleOps == "" {
		ruleOps = "v24_ruleops_admin"
	}
	approval := strings.TrimSpace(cfg.Approval)
	if approval == "" {
		approval = "v24_approval_admin"
	}
	breakGlass := strings.TrimSpace(cfg.BreakGlass)
	if breakGlass == "" {
		breakGlass = "v24_breakglass_admin"
	}
	profile := strings.TrimSpace(cfg.Profile)
	if profile == "" {
		profile = "v24_profile_admin"
	}
	loopRuns := strings.TrimSpace(cfg.LoopRuns)
	if loopRuns == "" {
		loopRuns = "v24_loop_admin"
	}
	circuit := strings.TrimSpace(cfg.Circuit)
	if circuit == "" {
		circuit = "v24_circuit_breaker_admin"
	}
	policyReload := strings.TrimSpace(cfg.PolicyReload)
	if policyReload == "" {
		policyReload = "v24_policy_reload_admin"
	}
	mid := cfg.MiddlewareStep
	if mid == 0 {
		mid = 16
	}

	return []ControlRoute{
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: ruleOps,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleDLPRulesets == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminDLPRulesetsPath) {
					return false
				}
				return routes.HandleDLPRulesets(w, r)
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: approval,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleApprovals == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminApprovalsPath) {
					return false
				}
				return routes.HandleApprovals(w, r)
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: breakGlass,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleBreakGlass == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminBreakGlassPath) {
					return false
				}
				return routes.HandleBreakGlass(w, r)
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: profile,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleProfiles == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminProfilesPath) {
					return false
				}
				return routes.HandleProfiles(w, r)
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: loopRuns,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleLoopRuns == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminLoopRunsPath) {
					return false
				}
				return routes.HandleLoopRuns(w, r)
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: circuit,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleCircuitBreaker == nil {
					return false
				}
				if hasAdminPrefix(r.URL.Path, adminCircuitBreakersPath+"/reset") || hasAdminPrefix(r.URL.Path, adminCircuitBreakersPath) {
					return routes.HandleCircuitBreaker(w, r)
				}
				return false
			},
		},
		{
			Reason:     "v24_admin_entry",
			Step:       mid,
			Middleware: policyReload,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandlePolicyReload == nil {
					return false
				}
				if !hasAdminPrefix(r.URL.Path, adminPolicyReloadPath) {
					return false
				}
				return routes.HandlePolicyReload(w, r)
			},
		},
		{
			Reason: "v24_admin_entry",
			Step:   mid,
			Try: func(w http.ResponseWriter, r *http.Request) bool {
				if routes.HandleFallback == nil {
					return false
				}
				if !IsAdminPath(r.URL.Path) {
					return false
				}
				return routes.HandleFallback(w, r)
			},
		},
	}
}

func hasAdminPrefix(path, prefix string) bool {
	if path == "" || len(prefix) == 0 {
		return false
	}
	if prefix == adminPolicyReloadPath {
		return path == prefix
	}
	return hasPathPrefix(path, prefix)
}

func hasPathPrefix(path, prefix string) bool {
	// Path equality and prefix checks for canonical path segments.
	return path == prefix || (len(path) > len(prefix) && path[:len(prefix)] == prefix)
}

func DispatchAdminRoutes(w http.ResponseWriter, r *http.Request, cfg AdminRouteConfig, routes AdminGatewayRoutes) bool {
	for _, route := range BuildAdminRoutes(cfg, routes) {
		if route.Try != nil && route.Try(w, r) {
			return true
		}
	}
	return false
}
