# Exfiltration Policy Tests - RFA-np7t
# Tests for exfiltration.rego rules including messaging_send

package mcp.exfiltration_test

import rego.v1
import data.mcp.exfiltration

test_exfiltration_risk_messaging_send if {
    exfiltration.exfiltration_risk with input as {
        "session": {
            "previous_actions": [
                {"tool": "database_query", "resource_classification": "sensitive"}
            ]
        },
        "action": {
            "tool": "messaging_send",
            "destination_external": true
        }
    }
}

test_no_exfiltration_risk_messaging_send_no_sensitive_prior if {
    not exfiltration.exfiltration_risk with input as {
        "session": {
            "previous_actions": [
                {"tool": "read", "resource_classification": "public"}
            ]
        },
        "action": {
            "tool": "messaging_send",
            "destination_external": true
        }
    }
}

test_exfiltration_deny_messaging_send_no_approval if {
    exfiltration.deny with input as {
        "session": {
            "previous_actions": [
                {"tool": "file_read", "resource_classification": "sensitive"}
            ]
        },
        "action": {
            "tool": "messaging_send",
            "destination_external": true,
            "human_approved": false
        }
    }
}

test_exfiltration_allow_messaging_send_with_approval if {
    exfiltration.allow with input as {
        "session": {
            "previous_actions": [
                {"tool": "file_read", "resource_classification": "sensitive"}
            ]
        },
        "action": {
            "tool": "messaging_send",
            "destination_external": true,
            "human_approved": true
        }
    }
}
