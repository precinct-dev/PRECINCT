# MCP-UI Security Policy Tests - RFA-9fv.6
# Tests for ui_policy.rego rules:
#   - deny_ui_resource: Block resources from unapproved servers
#   - deny_app_tool_call: Block app-driven calls to unapproved tools
#   - requires_step_up: Force step-up for high-risk app calls
#   - excessive_app_calls: Flag sessions with too many app calls

package mcp.ui.policy_test

import rego.v1
import data.mcp.ui.policy

# --------------------------------------------------------------------------
# Test data
# --------------------------------------------------------------------------
mock_grants := [
  {
    "server": "mcp-dashboard-server",
    "mode": "allow",
    "approved_tools": ["render-analytics", "show-chart"],
  },
  {
    "server": "mcp-reporting-server",
    "mode": "audit-only",
    "approved_tools": [],
  },
  {
    "server": "mcp-untrusted-server",
    "mode": "deny",
    "approved_tools": [],
  },
]

# --------------------------------------------------------------------------
# deny_ui_resource
# --------------------------------------------------------------------------
test_deny_ui_resource_unapproved_server if {
  policy.deny_ui_resource with input as {
    "ui": {"enabled": true},
    "tool_server": "mcp-unknown-server",
  }
    with data.ui_capability_grants as mock_grants
}

test_allow_ui_resource_approved_server if {
  not policy.deny_ui_resource with input as {
    "ui": {"enabled": true},
    "tool_server": "mcp-dashboard-server",
  }
    with data.ui_capability_grants as mock_grants
}

test_allow_ui_resource_when_disabled if {
  not policy.deny_ui_resource with input as {
    "ui": {"enabled": false},
    "tool_server": "mcp-unknown-server",
  }
    with data.ui_capability_grants as mock_grants
}

test_deny_ui_resource_denied_server if {
  # A server with mode "deny" should NOT satisfy ui_server_approved
  policy.deny_ui_resource with input as {
    "ui": {"enabled": true},
    "tool_server": "mcp-untrusted-server",
  }
    with data.ui_capability_grants as mock_grants
}

# --------------------------------------------------------------------------
# deny_app_tool_call
# --------------------------------------------------------------------------
test_deny_app_tool_call_unapproved_tool if {
  policy.deny_app_tool_call with input as {
    "ui": {"call_origin": "app"},
    "tool_server": "mcp-dashboard-server",
    "tool": "delete-data",
  }
    with data.ui_capability_grants as mock_grants
}

test_allow_app_tool_call_approved_tool if {
  not policy.deny_app_tool_call with input as {
    "ui": {"call_origin": "app"},
    "tool_server": "mcp-dashboard-server",
    "tool": "render-analytics",
  }
    with data.ui_capability_grants as mock_grants
}

test_allow_user_tool_call_any_tool if {
  # call_origin != "app" means this rule does not apply
  not policy.deny_app_tool_call with input as {
    "ui": {"call_origin": "user"},
    "tool_server": "mcp-dashboard-server",
    "tool": "delete-data",
  }
    with data.ui_capability_grants as mock_grants
}

# --------------------------------------------------------------------------
# requires_step_up
# --------------------------------------------------------------------------
test_requires_step_up_high_risk_app if {
  policy.requires_step_up with input as {
    "ui": {"call_origin": "app"},
    "tool_risk_level": "high",
  }
}

test_requires_step_up_critical_risk_app if {
  policy.requires_step_up with input as {
    "ui": {"call_origin": "app"},
    "tool_risk_level": "critical",
  }
}

test_no_step_up_low_risk_app if {
  not policy.requires_step_up with input as {
    "ui": {"call_origin": "app"},
    "tool_risk_level": "low",
  }
}

test_no_step_up_high_risk_user if {
  # User-initiated calls do not require step-up via this rule
  not policy.requires_step_up with input as {
    "ui": {"call_origin": "user"},
    "tool_risk_level": "high",
  }
}

# --------------------------------------------------------------------------
# excessive_app_calls
# --------------------------------------------------------------------------
test_excessive_app_calls_over_50 if {
  policy.excessive_app_calls with input as {
    "ui": {
      "call_origin": "app",
      "app_session_tool_calls": 51,
    },
  }
}

test_no_excessive_app_calls_under_50 if {
  not policy.excessive_app_calls with input as {
    "ui": {
      "call_origin": "app",
      "app_session_tool_calls": 49,
    },
  }
}

test_no_excessive_app_calls_at_50 if {
  not policy.excessive_app_calls with input as {
    "ui": {
      "call_origin": "app",
      "app_session_tool_calls": 50,
    },
  }
}

test_no_excessive_user_calls if {
  not policy.excessive_app_calls with input as {
    "ui": {
      "call_origin": "user",
      "app_session_tool_calls": 100,
    },
  }
}
