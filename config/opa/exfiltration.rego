# Exfiltration Detection Policy - RFA-qq0.15
# Detects patterns of sensitive data access followed by external transmission

package mcp.exfiltration

import rego.v1

# Detect exfiltration risk pattern:
# 1. Previous action accessed sensitive data (database_query, file_read, etc.)
# 2. Current action targets external destination (email, http, upload)
# 3. No human approval present
exfiltration_risk if {
    # Check if any previous action accessed sensitive data
    some prev_action in input.session.previous_actions
    prev_action.tool in ["database_query", "file_read", "grep", "search"]
    prev_action.resource_classification == "sensitive"

    # Check if current action targets external destination
    input.action.tool in ["email_send", "http_request", "file_upload", "webhook_call", "messaging_send"]
    input.action.destination_external == true
}

# Deny if exfiltration risk detected without human approval
deny if {
    exfiltration_risk
    not input.action.human_approved
}

# Allow with human approval
allow if {
    exfiltration_risk
    input.action.human_approved == true
}
