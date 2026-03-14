# MCP-UI Security Policy - RFA-j2d.7
# Based on Reference Architecture Section 7.9.8
#
# This policy package evaluates UI-specific security decisions for the MCP Apps
# extension (SEP-1865). It operates on the "ui" section of the OPA input document,
# which is populated by the gateway when processing UI-related requests.
#
# Rules:
#   deny_ui_resource    - Block UI resources from unapproved servers
#   deny_app_tool_call  - Block app-driven calls to unapproved tools
#   requires_step_up    - Force step-up auth for high-risk app-driven calls
#   excessive_app_calls - Flag sessions with too many app-driven tool calls
#
# Data dependencies:
#   data.ui_capability_grants - loaded from config/opa/ui_capability_grants.yaml

package mcp.ui.policy

import rego.v1

# Default: no denial, no step-up, no excessive calls
default deny_ui_resource := false

default deny_app_tool_call := false

default requires_step_up := false

default excessive_app_calls := false

# --- deny_ui_resource ---
# Block UI resources from servers that do not have an "allow" mode grant.
# Condition: UI is enabled AND the server is NOT approved.
deny_ui_resource if {
	input.ui.enabled
	not ui_server_approved
}

# A server is approved if there is a grant with mode "allow" matching
# the tool_server in the input.
ui_server_approved if {
	some grant in data.ui_capability_grants
	grant.server == input.tool_server
	grant.mode == "allow"
}

# --- deny_app_tool_call ---
# Block app-driven calls to tools that are not in the grant's approved_tools list.
# Only applies when call_origin is "app" and the grant has a non-empty approved_tools list.
deny_app_tool_call if {
	input.ui.call_origin == "app"
	some grant in data.ui_capability_grants
	grant.server == input.tool_server
	count(grant.approved_tools) > 0
	not input.tool in grant.approved_tools
}

# --- requires_step_up ---
# Force step-up authentication for app-driven calls to high-risk or critical tools.
requires_step_up if {
	input.ui.call_origin == "app"
	input.tool_risk_level in {"high", "critical"}
}

# --- excessive_app_calls ---
# Flag sessions where the app has made more than 50 tool calls, indicating
# potential automated abuse or runaway behavior.
excessive_app_calls if {
	input.ui.call_origin == "app"
	input.ui.app_session_tool_calls > 50
}
