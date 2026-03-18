# MCP Authorization Policy - RFA-qq0.5, RFA-qq0.19
# Based on Reference Architecture Section 6.4
# Implements path-based restrictions, step-up gating, and destination controls
# RFA-qq0.19: Adds poisoning pattern detection to identify malicious tool descriptions

package mcp

import rego.v1

# Load tool grants and tool registry from data files
tool_grants := data.tool_grants
tool_registry := data.tool_registry

# POC directory - allowed path for read/grep operations
# Reads from data.config.allowed_base_path injected at runtime by OPAEngine.
# Fail-closed: if not configured, no path will match (startswith check against
# the impossible sentinel value ensures read/grep are denied until properly configured).
default poc_directory := "__UNCONFIGURED_ALLOWED_BASE_PATH__"

poc_directory := data.config.allowed_base_path

# Main authorization decision
default allow := {
    "allow": false,
    "reason": "default_deny"
}

# Allow if all conditions pass:
# 1. SPIFFE ID matches a grant
# 2. Tool is authorized for that SPIFFE ID
# 3. Path restrictions are satisfied (for read/grep)
# 4. Destination restrictions are satisfied (for external egress)
# 5. Step-up requirements are met (for high-risk tools)
# 6. Session risk is acceptable (RFA-qq0.15)
# 7. OAuth scope requirements are met (OC-k6y0)
allow := {
    "allow": true,
    "reason": "allowed"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    session_risk_acceptable
    principal_level_acceptable
    oauth_scope_satisfied
}

# True when at least one grant matches the caller SPIFFE ID.
matching_grant_exists if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
}

# True when any matching grant authorizes the requested tool.
tool_authorized_for_spiffe(tool) if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(tool, grant.allowed_tools)
}

# RFA-qq0.15: Session risk check
# Risk score must be below 0.7 threshold
session_risk_acceptable if {
    input.session.risk_score < 0.7
}

session_risk_acceptable if {
    # No session data present - allow (backward compatible)
    not input.session
}

# Check if SPIFFE ID matches pattern
spiffe_matches(spiffe_id, pattern) if {
    # Exact match
    spiffe_id == pattern
}

spiffe_matches(spiffe_id, pattern) if {
    # Wildcard match: replace * with regex
    pattern_regex := replace(pattern, "*", "[^/]+")
    regex.match(pattern_regex, spiffe_id)
}

# Check if tool is in allowed list
tool_authorized(tool, allowed_tools) if {
    # Wildcard grants all tools
    "*" in allowed_tools
}

tool_authorized(tool, allowed_tools) if {
    # Tool explicitly listed
    tool in allowed_tools
}

tool_authorized("", allowed_tools) if {
    # Empty tool name (health checks, etc.) - allow
    true
}

# Path-based restrictions for read/grep
path_allowed(tool, params) if {
    # read tool - must be within POC directory
    tool == "read"
    file_path := params.file_path
    startswith(file_path, poc_directory)
}

path_allowed(tool, params) if {
    # grep tool - must be within POC directory
    tool == "grep"
    search_path := params.path
    startswith(search_path, poc_directory)
}

path_allowed(tool, params) if {
    # bash tool - no path restrictions (handled by step-up)
    tool == "bash"
}

path_allowed(tool, params) if {
    # tavily tools - no path restrictions
    startswith(tool, "tavily_")
}

path_allowed(tool, params) if {
    # Other tools or no params - pass through
    not tool in ["read", "grep"]
}

# Destination-based restrictions for external egress
destination_allowed(tool, params) if {
    # tavily tools - only allowed to tavily.com domain
    startswith(tool, "tavily_")
    true
}

destination_allowed(tool, params) if {
    # read, grep - local operations, no external egress
    tool in ["read", "grep"]
}

destination_allowed(tool, params) if {
    # bash - denied external egress by default
    # Would need explicit step-up and approval for external connections
    tool == "bash"
    # For POC, we block external egress from bash
    not contains(params.command, "curl")
    not contains(params.command, "wget")
    not contains(params.command, "http")
}

destination_allowed("messaging_send", dest) if {
    # messaging_send - only allowed to messaging-sim (POC)
    dest == "messaging-sim"
}

destination_allowed("messaging_send", params) if {
    # messaging_send - allow when params is not a string (object/map form)
    not is_string(params)
}

destination_allowed("messaging_status", params) if {
    # messaging_status - read-only status check, always allowed
    true
}

destination_allowed(tool, params) if {
    # Port-declared route authorization: port adapters register their routes
    # via data.port_route_authorizations (injected at runtime by the gateway).
    # This keeps the core policy generic -- no port-specific paths here.
    # All other OPA checks (SPIFFE grants, session risk, principal level) still apply.
    some route in data.port_route_authorizations
    port_route_matches(route)
}

# A port route matches when the request path and method align with the declaration.
port_route_matches(route) if {
    route.path == input.path
    input.method in route.methods
}

port_route_matches(route) if {
    not route.path
    startswith(input.path, route.path_prefix)
    input.method in route.methods
}

destination_allowed(tool, params) if {
    # Other tools - default deny external egress unless explicitly allowed
    not tool in ["tavily_search", "tavily_extract", "tavily_crawl", "tavily_map", "tavily_research", "read", "grep", "bash", "messaging_send", "messaging_status"]
    # Would check against tool registry allowed_destinations
    false
}

# Step-up gating for high-risk tools
step_up_satisfied(tool, step_up_token) if {
    # Check if tool requires step-up
    some registry_tool in tool_registry.tools
    registry_tool.name == tool
    registry_tool.requires_step_up == true

    # Verify step-up token is present
    step_up_token != ""
    step_up_token != null
}

step_up_satisfied(tool, step_up_token) if {
    # Tool doesn't require step-up
    some registry_tool in tool_registry.tools
    registry_tool.name == tool
    registry_tool.requires_step_up == false
}

step_up_satisfied(tool, step_up_token) if {
    # Tool not in registry - default to no step-up required (fail open for unknown tools)
    not tool_in_registry(tool)
}

step_up_satisfied("", step_up_token) if {
    # Empty tool name (health checks) - no step-up needed
    true
}

# Helper: check if tool is in registry
tool_in_registry(tool) if {
    some registry_tool in tool_registry.tools
    registry_tool.name == tool
}

# Detailed reason for denial
allow := {
    "allow": false,
    "reason": "no_matching_grant"
} if {
    not matching_grant_exists
}

allow := {
    "allow": false,
    "reason": "tool_not_authorized"
} if {
    matching_grant_exists
    not tool_authorized_for_spiffe(input.tool)
}

allow := {
    "allow": false,
    "reason": "path_denied"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    not path_allowed(input.tool, input.params)
}

allow := {
    "allow": false,
    "reason": "destination_denied"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    not destination_allowed(input.tool, input.params)
}

allow := {
    "allow": false,
    "reason": "step_up_required"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    not step_up_satisfied(input.tool, input.step_up_token)
}

allow := {
    "allow": false,
    "reason": "session_risk_too_high"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    not session_risk_acceptable
}


# OC-3ch6: Principal level insufficient for requested operation
allow := {
    "allow": false,
    "reason": "principal_level_insufficient"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    session_risk_acceptable
    not principal_level_acceptable
}

# OC-k6y0: OAuth scope missing for external principals
allow := {
    "allow": false,
    "reason": "oauth_scope_missing"
} if {
    matching_grant_exists
    tool_authorized_for_spiffe(input.tool)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
    session_risk_acceptable
    principal_level_acceptable
    not oauth_scope_satisfied
}

# ============================================================================
# OC-3ch6: Principal-aware authorization rules
# ============================================================================

default principal_level_acceptable := true

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 2
    is_destructive_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 1
    is_data_export_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level > 3
    is_messaging_action
}

principal_level_acceptable := false if {
    input.principal != null
    input.principal.level == 5
    input.path != "/health"
}

is_destructive_action if {
    action := lower(input.action)
    keywords := ["delete", "rm", "remove", "drop", "reset", "wipe", "shutdown", "terminate", "revoke", "purge", "destroy"]
    keyword := keywords[_]
    contains(action, keyword)
}

is_data_export_action if {
    action := lower(input.action)
    keywords := ["export", "dump", "backup", "extract", "exfil"]
    keyword := keywords[_]
    contains(action, keyword)
}

is_messaging_action if {
    action := lower(input.action)
    keywords := ["message", "notify", "broadcast", "send_agent", "agent_invoke"]
    keyword := keywords[_]
    contains(action, keyword)
}

# ============================================================================
# OC-k6y0: OAuth scope enforcement for external principals
# Deny-by-default: when auth_method is oauth_jwt or oauth_introspection,
# the caller must present the required MCP scope(s) in input.oauth_scopes.
# ============================================================================

# Non-OAuth auth methods are not subject to scope checks.
default oauth_scope_satisfied := true

# Override: when auth_method is OAuth-based, require scopes.
oauth_scope_satisfied := false if {
    is_oauth_auth_method
    not has_required_oauth_scope
}

# True when the auth method is an OAuth flow.
is_oauth_auth_method if {
    input.auth_method == "oauth_jwt"
}

is_oauth_auth_method if {
    input.auth_method == "oauth_introspection"
}

# Required scope depends on what is being invoked.
# When input.tool is non-empty, the request is a tools/call and requires
# "mcp:tools:call" scope plus any per-tool scopes from the grant.
# Note: tools/list is bypassed before reaching OPA by the gateway middleware,
# so scope enforcement for it lives there, not here.
has_required_oauth_scope if {
    input.tool != ""
    "mcp:tools:call" in input.oauth_scopes
    per_tool_scope_satisfied
}

# When input.tool is empty, the request is not a tool invocation (health check,
# protocol method, etc.). No tool-plane scope is needed.
has_required_oauth_scope if {
    input.tool == ""
}

# Per-tool scope: if a grant for the matching SPIFFE pattern specifies
# required_scopes for the requested tool, the caller must hold those scopes.
# Grants without required_scopes impose no per-tool scope requirement.
per_tool_scope_satisfied if {
    # Find the matching grant
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)

    # Check if this grant has required_scopes for the tool
    required := object.get(grant, "required_scopes", {})
    tool_scopes := object.get(required, input.tool, [])

    # Every required scope must be present in the caller's scopes
    every scope in tool_scopes {
        scope in input.oauth_scopes
    }
}

# RFA-qq0.19: Poisoning pattern detection
# Check if tool description contains poisoning indicators
contains_poisoning_indicators(description) if {
    # Pattern 1: <IMPORTANT> tag
    regex.match(`(?i)<IMPORTANT>.*?</IMPORTANT>`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 2: <SYSTEM> tag
    regex.match(`(?i)<SYSTEM>.*?</SYSTEM>`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 3: HTML comment
    regex.match(`(?i)<!--.*?-->`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 4: before using...first instruction
    regex.match(`(?i)before\s+using\s+this\s+tool.*?first`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 5: ignore instructions command
    regex.match(`(?i)ignore\s+(previous|all|prior)\s+instructions`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 6: you must command
    regex.match(`(?i)you\s+must\s+(always|first|never)`, description)
}

contains_poisoning_indicators(description) if {
    # Pattern 7: send to external destination
    regex.match(`(?i)send.*?(email|http|webhook|upload).*?to`, description)
}
