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
    # tavily_search - no path restrictions
    tool == "tavily_search"
}

path_allowed(tool, params) if {
    # Other tools or no params - pass through
    not tool in ["read", "grep"]
}

# Destination-based restrictions for external egress
destination_allowed(tool, params) if {
    # tavily_search - only allowed to tavily.com domain
    tool == "tavily_search"
    # In real implementation, would check actual destination from params
    # For POC, we trust that tavily_search only connects to tavily.com
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
    # Other tools - default deny external egress unless explicitly allowed
    not tool in ["tavily_search", "read", "grep", "bash", "messaging_send", "messaging_status"]
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
