# OC-xj4w: Port-scoped trusted agent policy for OpenClaw.
#
# This policy overlay determines whether a given SPIFFE ID is a trusted agent
# eligible for DLP bypass on system prompt content. It loads trusted agent
# definitions from data.trusted_agents (populated from trusted_agents.yaml).
#
# The bypass scope is narrow: only messages with role="system" skip DLP
# scanning. User messages (role="user") are always scanned regardless of
# trusted agent status.
#
# This file lives in ports/openclaw/policy/ and is loaded as a data overlay
# alongside core config/opa/ policies. Core policy files are NOT modified.

package precinct.port.openclaw.trusted_agents

import rego.v1

# is_trusted_agent is true when the caller's SPIFFE ID matches a trusted
# agent entry with dlp_bypass_scope="system_prompt".
default is_trusted_agent := false

is_trusted_agent if {
    some agent in data.trusted_agents
    agent.spiffe_id == input.spiffe_id
    agent.dlp_bypass_scope == "system_prompt"
}

# bypass_dlp_for_role returns true when the given message role qualifies
# for DLP bypass under the trusted agent policy.
# Only role="system" messages are bypassed; all other roles are scanned.
default bypass_dlp_for_role := false

bypass_dlp_for_role if {
    is_trusted_agent
    input.message_role == "system"
}
