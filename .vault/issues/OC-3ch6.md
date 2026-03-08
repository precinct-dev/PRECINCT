---
id: OC-3ch6
title: "OPA Policy Extensions for Principal-Aware Authorization"
status: open
priority: 2
type: task
labels: [agents-of-chaos, principal-hierarchy]
parent: OC-qkal
created_at: 2026-03-08T02:42:52Z
created_by: ramirosalas
updated_at: 2026-03-08T02:42:52Z
content_hash: "sha256:8b9e028d0baee9c83aed8ea7485ad5bbf345c0a1c95c0aaec78d5ecacc4dd340"
blocked_by: [OC-70gv, OC-t7go]
blocks: [OC-f0xy]
---

## Description
## User Story

As a security operator, I need OPA policies that enforce principal-level-aware authorization so that destructive operations are restricted to owner-level principals, data export requires owner authorization, and external users cannot access inter-agent communication tools.

## Context

Story OC-70gv defines the principal hierarchy (Level 0-5). Story OC-t7go injects principal metadata into request context and headers. This story extends existing OPA policies with principal-level-aware rules.

Existing OPA policies in POC/config/opa/:
- mcp_policy.rego: tool-level authorization grants by SPIFFE ID
- ui_policy.rego: MCP-UI capability gating
- exfiltration.rego: cross-tool data flow detection
- context_policy.rego: context-aware authorization
- ui_csp_policy.rego: content security policy enforcement

OPAInput struct: SPIFFEID string, Tool string, Action string, Method string, Path string, Params map[string]interface{}, StepUpToken string, Session SessionInput, UI *UIInput.

## Implementation

1. Extend OPAInput with PrincipalRole:
```go
type OPAInput struct {
    SPIFFEID    string                 `json:"spiffe_id"`
    Tool        string                 `json:"tool"`
    Action      string                 `json:"action"`
    Method      string                 `json:"method"`
    Path        string                 `json:"path"`
    Params      map[string]interface{} `json:"params"`
    StepUpToken string                 `json:"step_up_token"`
    Session     SessionInput           `json:"session"`
    UI          *UIInput               `json:"ui,omitempty"`
    DataSource  *DataSourceInput       `json:"data_source,omitempty"`
    Principal   *PrincipalInput        `json:"principal,omitempty"`
}

type PrincipalInput struct {
    Level        int      `json:"level"`
    Role         string   `json:"role"`
    Capabilities []string `json:"capabilities"`
}
```

2. Extend existing policies with principal-aware rules. Add to mcp_policy.rego or create dedicated sections:

Destructive operations require principal_level <= 2:
```rego
deny["principal_level_insufficient_destructive"] {
    destructive_action
    input.principal.level > 2
}

destructive_action {
    input.action == "delete"
}
destructive_action {
    input.action == "shutdown"
}
destructive_action {
    input.action == "reset"
}
```

Data export requires principal_level <= 1:
```rego
deny["principal_level_insufficient_export"] {
    data_export_action
    input.principal.level > 1
}
data_export_action {
    input.action == "export"
}
```

Inter-agent messaging requires principal_level <= 3:
```rego
deny["principal_level_insufficient_messaging"] {
    inter_agent_messaging
    input.principal.level > 3
}
inter_agent_messaging {
    input.tool == "messaging_send"
}
```

Anonymous (level 5) denied except health checks:
```rego
deny["anonymous_denied"] {
    input.principal.level == 5
    input.path != "/health"
}
```

New error code: "principal_level_insufficient" (step 6, HTTP 403, middleware "opa_policy")

## Key Files

- POC/internal/gateway/middleware/opa.go (modify -- add PrincipalInput and Principal field)
- POC/config/opa/mcp_policy.rego (modify -- add principal-aware rules)
- POC/internal/gateway/middleware/error_codes.go (modify -- add principal_level_insufficient)

## Testing

- Unit tests: each principal level against each operation category (owner+delete -> allow, external+delete -> deny, agent+messaging -> allow, external+messaging -> deny, anonymous+anything -> deny except health)
- Integration test: external user (spiffe://poc.local/external/bob, Level=4) denied destructive operation; owner (spiffe://poc.local/owner/alice, Level=1) allowed same operation

## Acceptance Criteria

1. PrincipalInput struct added to OPAInput with Level, Role, Capabilities
2. Destructive operations (delete, shutdown, reset) require principal_level <= 2
3. Data export operations require principal_level <= 1
4. Inter-agent messaging requires principal_level <= 3
5. Anonymous (level 5) denied except /health
6. New error code "principal_level_insufficient" added to error_codes.go
7. Unit tests cover each principal level against each operation category
8. Integration test demonstrates level-based access control

## Dependencies

Depends on OC-70gv (PrincipalRole resolution), OC-t7go (principal metadata in context).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:43:16Z dep_added: blocks OC-f0xy

## Links
- Parent: [[OC-qkal]]
- Blocks: [[OC-f0xy]]
- Blocked by: [[OC-70gv]], [[OC-t7go]]

## Comments
