# MCP Authorization Policy
# Based on Reference Architecture Section 6.4

package mcp

import future.keywords.if
import future.keywords.in

# Load tool grants and tool registry from data files
tool_grants := data.tool_grants
tool_registry := data.tool_registry

# POC directory - allowed path for read/grep operations
poc_directory := "/Users/ramirosalas/workspace/agentic_reference_architecture/POC"

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
allow := {
    "allow": true,
    "reason": "allowed"
} if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    step_up_satisfied(input.tool, input.step_up_token)
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

destination_allowed(tool, params) if {
    # Other tools - default deny external egress unless explicitly allowed
    not tool in ["tavily_search", "read", "grep", "bash"]
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
    count([grant | some grant in tool_grants; spiffe_matches(input.spiffe_id, grant.spiffe_pattern)]) == 0
}

allow := {
    "allow": false,
    "reason": "tool_not_authorized"
} if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    not tool_authorized(input.tool, grant.allowed_tools)
}

allow := {
    "allow": false,
    "reason": "path_denied"
} if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)
    not path_allowed(input.tool, input.params)
}

allow := {
    "allow": false,
    "reason": "destination_denied"
} if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)
    path_allowed(input.tool, input.params)
    not destination_allowed(input.tool, input.params)
}

allow := {
    "allow": false,
    "reason": "step_up_required"
} if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)
    path_allowed(input.tool, input.params)
    destination_allowed(input.tool, input.params)
    not step_up_satisfied(input.tool, input.step_up_token)
}
