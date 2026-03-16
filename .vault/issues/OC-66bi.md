---
id: OC-66bi
title: "OPA input.action hardcoded to 'execute' -- principal-level rules for destructive/messaging actions never fire end-to-end"
status: closed
priority: 0
type: bug
parent: OC-qkal
created_at: 2026-03-08T07:40:16Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:304478ce07c23d3980dfe0e50471a5fd31562c620b88e27572cf4335c62fb56d"
related: [OC-3ch6]
follows: [OC-3ch6]
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## Context

The OPA middleware in `POC/internal/gateway/middleware/opa.go` hardcodes `Action: "execute"` at line 245 when building the OPAInput struct for policy evaluation. The OPA policy in `POC/config/opa/mcp_policy.rego` contains principal-level-aware rules (added in OC-3ch6) that check `input.action` for semantic keywords:

- `is_destructive_action` checks for: delete, rm, remove, drop, reset, wipe, shutdown, terminate, revoke, purge, destroy
- `is_data_export_action` checks for: export, dump, backup, extract, exfil
- `is_messaging_action` checks for: message, notify, broadcast, send_agent, agent_invoke

Since the Action field is always `"execute"`, none of these keyword checks can ever match via the actual gateway HTTP path. This means `principal_level_acceptable` always evaluates to `true` (its default), and principal-level authorization is effectively a no-op for all HTTP requests.

Unit and integration tests for OC-3ch6 pass because they construct the OPAInput struct directly with Action set to test-specific values (e.g., "delete", "message"), bypassing the middleware's hardcoded assignment.

## Root Cause

Line 245 of `POC/internal/gateway/middleware/opa.go`:
```go
Action: "execute",
```

The Action field should be derived from the request context -- either from `params["action"]` in the MCP request body, from the tool name (e.g., tool name contains "delete" or "messaging_send"), or from a combination of both. The OPA policy's keyword-matching rules were written to work with semantically meaningful Action values, but the middleware never provides them.

## Affected Components

- `POC/internal/gateway/middleware/opa.go` -- Action field hardcoded to "execute" (line 245)
- `POC/config/opa/mcp_policy.rego` -- principal_level_acceptable rules (lines 288-332) are correct but unreachable via HTTP
- E2E demo scenarios S-PRINCIPAL-2 and S-PRINCIPAL-4 (story OC-f0xy) will produce incorrect results

## Acceptance Criteria

- [ ] OPA middleware derives `Action` from request semantics (params["action"], tool name, or both) instead of hardcoding "execute"
- [ ] When a request carries params["action"]="delete", the OPAInput.Action is "delete" (not "execute")
- [ ] When the tool name is "messaging_send" and no explicit action param exists, the Action field contains a value that triggers `is_messaging_action` (e.g., the tool name itself or a derived action like "message")
- [ ] Fallback: if no action can be derived from params or tool name, Action defaults to "execute" (preserving backward compatibility for tools that have no action semantics)
- [ ] E2E validation: external user (level 4) calling a destructive action receives HTTP 403 with "principal_level_insufficient" through the actual gateway HTTP path (not just unit tests)
- [ ] E2E validation: external user (level 4) calling messaging_send receives HTTP 403 with "principal_level_insufficient" through the actual gateway HTTP path
- [ ] Existing OPA unit and integration tests continue to pass (no regression)
- [ ] Integration test added that exercises the full middleware chain (not just OPAInput struct construction) to prevent this class of bypass in the future

## Testing Requirements

- Unit tests: verify Action derivation logic for various param combinations (explicit action param, tool-name fallback, no-action fallback)
- Integration tests: MANDATORY (no mocks) -- full HTTP request through gateway middleware chain, verifying that principal-level deny rules fire for destructive/messaging actions

## Discovered During

Story OC-f0xy (E2E Demo -- Principal Hierarchy Enforcement): demo scenarios S-PRINCIPAL-2 and S-PRINCIPAL-4 would produce wrong results because the OPA rules checking input.action can never match "execute" against destructive/messaging keywords.

## Notes

The OPA policy (OC-3ch6) is correct -- the rules themselves are well-structured and the keyword matching is sound. The bug is purely in the Go middleware's failure to populate the Action field with semantically meaningful values. The fix belongs in opa.go, not in the rego policies.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z dep_removed: no_longer_blocks OC-f0xy

## Links
- Parent: [[OC-qkal]]
- Related: [[OC-3ch6]]
- Follows: [[OC-3ch6]]

## Comments

### 2026-03-08T07:40:25Z ramirosalas
DECISION: The fix belongs in opa.go (Go middleware), NOT in mcp_policy.rego (OPA policy). OC-3ch6's rego rules are correct -- they check input.action for semantic keywords as designed. The problem is that the middleware never populates input.action with meaningful values. The rego policy should NOT be changed to work around the hardcoded 'execute' value.
