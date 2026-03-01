---
id: RFA-np7t
title: "Extend OPA policy, config, and exfiltration rules for all messaging tools with tests"
status: closed
priority: 1
type: task
parent: RFA-xynt
created_at: 2026-02-27T04:28:57Z
created_by: ramirosalas
updated_at: 2026-02-27T05:38:59Z
content_hash: "sha256:fcd28b86561c53bf93c00ae57bc8ffbb397dddff29bd1ad62a1171a373ffaeb3"
blocks: [RFA-mbmr, RFA-yt63]
related: [RFA-ncf1, RFA-zxnh]
labels: [ready, accepted]
blocked_by: [RFA-1fui]
follows: [RFA-1fui]
closed_at: 2026-02-27T05:38:59Z
close_reason: "Accepted: All 10 ACs verified. messaging_status added to both tool registries (risk_level:low, requires_step_up:false, required_scope:tools.messaging.status). messaging_send allowed_destinations extended with production WhatsApp/Telegram/Slack domains in both registries. exfiltration.rego includes messaging_send in external tools list. destinations.yaml has all 5 production messaging domains. mcp_policy.rego has destination_allowed rule for messaging_status. mcp_policy_test.rego has both destination tests. exfiltration_test.rego exists with all 4 required test cases (logically valid against policy rules). session_context.go externalTools includes messaging_status. Attestation artifacts re-signed after registry change. 73/73 OPA tests and 19/19 Go packages."
led_to: [RFA-mbmr, RFA-zxnh, RFA-cweb, RFA-yt63]
---

## Description
## User Story
As the gateway operator, I need messaging tools fully registered in config, OPA policy, destination allowlist, and the session context externalTools set -- with comprehensive OPA test coverage -- so that the middleware chain correctly evaluates, rate-limits, DLP-scans, and detects exfiltration for all messaging operations.

## Context
The walking skeleton (RFA-1fui) established the minimal config for `messaging_send` (tool registry entry, destination `messaging-sim`, externalTools map entry, minimal OPA destination_allowed rule). This story extends the config to full production scope: adds `messaging_status` tool, adds all production destination domains, updates the exfiltration rule, and ADDS COMPREHENSIVE OPA TESTS.

## What to Change

### 1. `config/tool-registry.yaml` -- Add messaging_status tool

The walking skeleton already added `messaging_send`. This story adds:

```yaml
  - name: "messaging_status"
    description: "Check delivery status of a previously sent message"
    hash: "<compute with scripts/compute_tool_hashes.go>"
    input_schema:
      type: "object"
      required: ["platform", "message_id"]
      properties:
        platform:
          type: "string"
          enum: ["whatsapp", "telegram", "slack"]
        message_id:
          type: "string"
    risk_level: "low"
    requires_step_up: false
    required_scope: "tools.messaging.status"
```

Update `messaging_send` allowed_destinations to include production domains:
```yaml
    allowed_destinations:
      - "graph.facebook.com"
      - "*.facebook.com"
      - "api.telegram.org"
      - "slack.com"
      - "*.slack.com"
      - "messaging-sim"
```

### 2. `config/opa/tool_registry.yaml` -- Mirror both tool entries

Add `messaging_status` and update `messaging_send` with production domains.

### 3. `config/opa/exfiltration.rego` -- Add `messaging_send` to external tools list

Change line 19 from:
```rego
    input.action.tool in ["email_send", "http_request", "file_upload", "webhook_call"]
```
to:
```rego
    input.action.tool in ["email_send", "http_request", "file_upload", "webhook_call", "messaging_send"]
```

### 4. `config/opa/mcp_policy.rego` -- Add destination rule for messaging_status

The walking skeleton added the `messaging_send` destination_allowed rule. This story adds:

```rego
destination_allowed(tool, params) if {
    tool == "messaging_status"
}
```

### 5. `config/destinations.yaml` -- Add production messaging domains

The walking skeleton added `messaging-sim`. This story adds:
```yaml
  - "graph.facebook.com"
  - "*.facebook.com"
  - "api.telegram.org"
  - "slack.com"
  - "*.slack.com"
```

### 6. NEW: OPA Policy Tests for Messaging Tools

#### `config/opa/mcp_policy_test.rego` -- Add destination tests

Add the following test cases after the existing `test_destination_denied_bash_wget` test:

```rego
# --- Messaging destination tests (RFA-xynt) ---

test_destination_allowed_messaging_send if {
    mcp.destination_allowed("messaging_send", {})
}

test_destination_allowed_messaging_status if {
    mcp.destination_allowed("messaging_status", {})
}
```

#### `config/opa/exfiltration_test.rego` -- NEW FILE: Exfiltration tests

Create `config/opa/exfiltration_test.rego`:

```rego
# Exfiltration Policy Tests - RFA-xynt
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
```

## Acceptance Criteria
1. `config/tool-registry.yaml` contains `messaging_status` (risk_level: low, requires_step_up: false) and `messaging_send` has production domains in allowed_destinations
2. `config/opa/tool_registry.yaml` mirrors both tool entries with production domains
3. `config/opa/exfiltration.rego` includes `messaging_send` in the external tools list on the exfiltration_risk rule
4. `config/opa/mcp_policy.rego` has `destination_allowed` rule for `messaging_status`
5. `config/destinations.yaml` includes production messaging domains: `graph.facebook.com`, `*.facebook.com`, `api.telegram.org`, `slack.com`, `*.slack.com`
6. `config/opa/mcp_policy_test.rego` includes `test_destination_allowed_messaging_send` and `test_destination_allowed_messaging_status` tests
7. `config/opa/exfiltration_test.rego` exists with tests for: exfiltration risk via messaging_send, no risk without sensitive prior action, deny without approval, allow with approval
8. All OPA tests pass: `opa test config/opa/ -v` (or equivalent)
9. `go build ./...` succeeds after changes
10. Existing unit tests (`go test ./internal/gateway/... && go test ./internal/gateway/middleware/...`) continue to pass

## Technical Notes
- The hash computation tool is at `scripts/compute_tool_hashes.go` -- run it after adding the tool entries
- The externalTools map in session_context.go was already updated by the walking skeleton
- The walking skeleton already added the minimal `messaging_send` destination_allowed rule; this story adds `messaging_status`
- OPA test runner: `opa test config/opa/ -v` runs all `*_test.rego` files
- The exfiltration.rego package is `mcp.exfiltration`, so test package should be `mcp.exfiltration_test`

## Testing Requirements
- OPA policy tests: `test_destination_allowed_messaging_send`, `test_destination_allowed_messaging_status` in mcp_policy_test.rego
- OPA exfiltration tests: 4 test cases in exfiltration_test.rego (risk detection, no risk, deny without approval, allow with approval)
- Existing Go unit tests must continue to pass

## Scope Boundary
This story changes config/policy files, adds OPA tests, and does NOT modify gateway Go code (the walking skeleton already updated session_context.go). Gateway egress, WS handler, and simulator are handled by sibling stories.

## Dependencies
- Requires RFA-1fui (walking skeleton) -- minimal config already established

## MANDATORY SKILLS TO REVIEW
- None identified. Config file edits, OPA rego test authoring, no specialized skill requirements.

## History
- 2026-02-27T05:38:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-xynt]]
- Blocks: [[RFA-mbmr]], [[RFA-yt63]]
- Blocked by: [[RFA-1fui]]
- Related: [[RFA-ncf1]], [[RFA-zxnh]]
- Follows: [[RFA-1fui]]
- Led to: [[RFA-mbmr]], [[RFA-zxnh]], [[RFA-cweb]], [[RFA-yt63]]

## Comments

### 2026-02-27T05:32:02Z ramirosalas
COMPLETED: All 10 ACs implemented and verified. 13 files changed, 151 insertions. OPA 73/73 tests pass, Go 19/19 packages pass. Commit 548f8d5 on epic/RFA-xynt-ws-mediation-messaging.
