# MCP-UI CSP Mediation Policy Tests - RFA-9fv.6
# Tests for ui_csp_policy.rego rules:
#   - denied_connect_domains: Connect domains not in allowlist
#   - denied_frame_domains: All frame domains denied (hard constraint)
#   - denied_permissions: Permissions not in allowed list

package mcp.ui.csp_test

import rego.v1
import data.mcp.ui.csp

# --------------------------------------------------------------------------
# Test data: per-server grants (keyed by server name for CSP policy)
# --------------------------------------------------------------------------
mock_grants := {
  "mcp-dashboard-server": {
    "allowed_csp_connect_domains": [
      "https://api.acme.corp",
      "https://*.cdn.acme.corp",
    ],
    "allowed_permissions": ["clipboard-read"],
  },
}

# --------------------------------------------------------------------------
# denied_connect_domains
# --------------------------------------------------------------------------
test_connect_domain_allowed if {
  result := csp.denied_connect_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": ["https://api.acme.corp"],
        "frameDomains": [],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

test_connect_domain_denied if {
  result := csp.denied_connect_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": ["https://evil.com"],
        "frameDomains": [],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  "https://evil.com" in result
}

test_connect_domain_wildcard_match if {
  result := csp.denied_connect_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": ["https://img.cdn.acme.corp"],
        "frameDomains": [],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

test_connect_domain_mixed if {
  result := csp.denied_connect_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": ["https://api.acme.corp", "https://evil.com", "https://also-evil.com"],
        "frameDomains": [],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 2
  "https://evil.com" in result
  "https://also-evil.com" in result
}

# --------------------------------------------------------------------------
# denied_frame_domains
# --------------------------------------------------------------------------
test_frame_domains_all_denied if {
  result := csp.denied_frame_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": [],
        "frameDomains": ["https://embed.example.com"],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  "https://embed.example.com" in result
}

test_frame_domains_empty_string_allowed if {
  result := csp.denied_frame_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": [],
        "frameDomains": [""],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

test_frame_domains_none if {
  result := csp.denied_frame_domains with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {
        "connectDomains": [],
        "frameDomains": [],
      },
      "permissions": {},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

# --------------------------------------------------------------------------
# denied_permissions
# --------------------------------------------------------------------------
test_permission_allowed if {
  result := csp.denied_permissions with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {"connectDomains": [], "frameDomains": []},
      "permissions": {"clipboard-read": true},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

test_permission_denied if {
  result := csp.denied_permissions with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {"connectDomains": [], "frameDomains": []},
      "permissions": {"camera": true},
    },
  }
    with data.ui_capability_grants as mock_grants

  "camera" in result
}

test_permission_false_not_denied if {
  result := csp.denied_permissions with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {"connectDomains": [], "frameDomains": []},
      "permissions": {"camera": false},
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 0
}

test_multiple_permissions_mixed if {
  result := csp.denied_permissions with input as {
    "server": "mcp-dashboard-server",
    "ui_meta": {
      "csp": {"connectDomains": [], "frameDomains": []},
      "permissions": {
        "clipboard-read": true,
        "camera": true,
        "microphone": true,
      },
    },
  }
    with data.ui_capability_grants as mock_grants

  count(result) == 2
  "camera" in result
  "microphone" in result
}
