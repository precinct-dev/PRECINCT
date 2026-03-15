# MCP-UI CSP Mediation Policy - RFA-j2d.3
# Based on Reference Architecture Section 7.9.4
#
# This policy package evaluates CSP and permissions mediation decisions for the
# MCP Apps extension. It operates on the "ui_meta" section of the OPA input
# document, which contains the server-declared _meta.ui.csp and _meta.ui.permissions.
#
# Rules:
#   denied_connect_domains  - Connect domains not in the grant's allowlist
#   denied_frame_domains    - All frame domains (hard constraint: always denied)
#   denied_permissions      - Permissions not in the grant's allowed_permissions
#
# Data dependencies:
#   data.ui_capability_grants - loaded from config/opa/ui_capability_grants.yaml
#
# Input format:
#   input.server     - The MCP server name
#   input.ui_meta.csp.connectDomains   - Server-declared connect domains
#   input.ui_meta.csp.frameDomains     - Server-declared frame domains
#   input.ui_meta.permissions          - Map of permission name to boolean

package mcp.ui.csp

import rego.v1

# --- denied_connect_domains ---
# Domains in connectDomains that are NOT in the grant's allowed_csp_connect_domains.
# These should be stripped by the gateway before forwarding to the host.
denied_connect_domains contains domain if {
	some domain in input.ui_meta.csp.connectDomains
	not domain_allowed(domain, data.ui_capability_grants[input.server].allowed_csp_connect_domains)
}

# --- denied_frame_domains ---
# ALL frame domains are denied (hard constraint). Nested iframes within MCP Apps
# are never permitted by gateway policy, regardless of what the server declares.
denied_frame_domains contains domain if {
	some domain in input.ui_meta.csp.frameDomains
	domain != ""
}

# --- denied_permissions ---
# Permissions set to true that are NOT in the grant's allowed_permissions list.
# The gateway should set these to false before forwarding.
denied_permissions contains perm if {
	some perm in object.keys(input.ui_meta.permissions)
	input.ui_meta.permissions[perm] == true
	not perm in data.ui_capability_grants[input.server].allowed_permissions
}

# --- Helper: domain_allowed ---
# Checks if a domain matches any entry in the allowlist using glob matching.
# Supports wildcard patterns (e.g., "*.example.com" matches "api.example.com").
domain_allowed(domain, allowlist) if {
	some allowed in allowlist
	glob.match(allowed, [], domain)
}
