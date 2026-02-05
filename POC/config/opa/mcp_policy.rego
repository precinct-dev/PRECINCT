# MCP Authorization Policy
# Based on Reference Architecture Section 6.4

package mcp

import future.keywords.if
import future.keywords.in

# Load tool grants from data file
tool_grants := data.tool_grants

# Main authorization decision
default allow := false

# Allow if SPIFFE ID matches a grant and tool is authorized
allow if {
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    tool_authorized(input.tool, grant.allowed_tools)
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

# Reason for denial
reason := "no_matching_grant" if {
    not allow
    count([grant | some grant in tool_grants; spiffe_matches(input.spiffe_id, grant.spiffe_pattern)]) == 0
}

reason := "tool_not_authorized" if {
    not allow
    some grant in tool_grants
    spiffe_matches(input.spiffe_id, grant.spiffe_pattern)
    not tool_authorized(input.tool, grant.allowed_tools)
}

reason := "allowed" if {
    allow
}
