# OC-xj4w: Tests for port-scoped trusted agent policy.
# Verifies that the trusted agent DLP bypass works correctly for
# system prompts while continuing to enforce DLP on user messages.

package precinct.port.openclaw.trusted_agents_test

import rego.v1
import data.precinct.port.openclaw.trusted_agents

# --------------------------------------------------------------------------
# Test data
# --------------------------------------------------------------------------
mock_trusted_agents := [
  {
    "spiffe_id": "spiffe://poc.local/openclaw",
    "dlp_bypass_scope": "system_prompt",
    "trust_tier": "port_scoped",
  },
]

# --------------------------------------------------------------------------
# is_trusted_agent tests
# --------------------------------------------------------------------------
test_openclaw_is_trusted_agent if {
  trusted_agents.is_trusted_agent with input as {"spiffe_id": "spiffe://poc.local/openclaw"}
    with data.trusted_agents as mock_trusted_agents
}

test_unknown_agent_is_not_trusted if {
  not trusted_agents.is_trusted_agent with input as {"spiffe_id": "spiffe://poc.local/other-agent"}
    with data.trusted_agents as mock_trusted_agents
}

test_empty_spiffe_is_not_trusted if {
  not trusted_agents.is_trusted_agent with input as {"spiffe_id": ""}
    with data.trusted_agents as mock_trusted_agents
}

test_no_trusted_agents_data if {
  not trusted_agents.is_trusted_agent with input as {"spiffe_id": "spiffe://poc.local/openclaw"}
    with data.trusted_agents as []
}

# --------------------------------------------------------------------------
# bypass_dlp_for_role tests
# --------------------------------------------------------------------------
test_bypass_system_role_for_trusted_agent if {
  trusted_agents.bypass_dlp_for_role with input as {
    "spiffe_id": "spiffe://poc.local/openclaw",
    "message_role": "system",
  } with data.trusted_agents as mock_trusted_agents
}

test_no_bypass_user_role_for_trusted_agent if {
  not trusted_agents.bypass_dlp_for_role with input as {
    "spiffe_id": "spiffe://poc.local/openclaw",
    "message_role": "user",
  } with data.trusted_agents as mock_trusted_agents
}

test_no_bypass_assistant_role_for_trusted_agent if {
  not trusted_agents.bypass_dlp_for_role with input as {
    "spiffe_id": "spiffe://poc.local/openclaw",
    "message_role": "assistant",
  } with data.trusted_agents as mock_trusted_agents
}

test_no_bypass_system_role_for_untrusted_agent if {
  not trusted_agents.bypass_dlp_for_role with input as {
    "spiffe_id": "spiffe://poc.local/other-agent",
    "message_role": "system",
  } with data.trusted_agents as mock_trusted_agents
}

test_no_bypass_empty_role if {
  not trusted_agents.bypass_dlp_for_role with input as {
    "spiffe_id": "spiffe://poc.local/openclaw",
    "message_role": "",
  } with data.trusted_agents as mock_trusted_agents
}
