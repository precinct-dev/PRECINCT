---
id: OC-4zrf
title: "OPA Policy for Data Source Access Control"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, data-source-integrity, delivered, accepted]
parent: OC-yrwz
created_at: 2026-03-08T02:39:03Z
created_by: ramirosalas
updated_at: 2026-03-09T01:34:38Z
content_hash: "sha256:340428e84c36da822a5b42a7498155aff648c9907a1246a0426201e92807fdc8"
related: [OC-am3w]
was_blocked_by: [OC-cqj0]
follows: [OC-cqj0]
closed_at: 2026-03-09T01:34:38Z
close_reason: "Accepted: DataSourceInput struct, OPAInput.DataSource field, data_source_policy.rego, grants YAML, DataSourcePolicyEvaluator interface, EvaluateDataSourcePolicy method, and 19 tests (all passing) delivered. Integration test uses real OPA engine with no mocks. Glob matching for SPIFFE/URI patterns verified correct. Library-scoped per epic design -- wiring happens in OC-am3w."
led_to: [OC-9aac]
---

## Description
## User Story

As a security operator, I need OPA policies that control which SPIFFE IDs can access which data source URIs so that unauthorized agents cannot fetch sensitive registered data sources, and high-risk sessions are blocked from accessing unregistered external URIs.

## Context

The existing OPA policy system (step 6, POC/internal/gateway/middleware/opa.go) evaluates authorization using OPAInput struct: SPIFFEID string (json:"spiffe_id"), Tool string (json:"tool"), Action string (json:"action"), Method string (json:"method"), Path string (json:"path"), Params map[string]interface{} (json:"params"), StepUpToken string (json:"step_up_token"), Session SessionInput (json:"session"), UI *UIInput (json:"ui").

SessionInput: RiskScore float64, PreviousActions []ToolAction.

OPA policies live in POC/config/opa/: mcp_policy.rego, ui_policy.rego, exfiltration.rego, context_policy.rego, ui_csp_policy.rego.

Config.OPAPolicyDir specifies the directory containing .rego files. OPA is embedded (not sidecar) -- policies are loaded at startup and hot-reloaded.

## Implementation

1. Extend OPAInput struct with DataSource field:
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
}

type DataSourceInput struct {
    URI            string `json:"uri"`
    Registered     bool   `json:"registered"`
    MutablePolicy  string `json:"mutable_policy"`
    ContentChanged bool   `json:"content_changed"`
}
```

2. Create new policy file POC/config/opa/data_source_policy.rego:
```rego
package precinct.data_source

default allow = false

# Registered data sources: check identity access
allow {
    input.data_source.registered == true
    data_source_grant[_]
}

# Data source grants by SPIFFE ID pattern
data_source_grant[grant] {
    grant := data.data_source_grants[_]
    glob.match(grant.spiffe_pattern, ["/"], input.spiffe_id)
    glob.match(grant.uri_pattern, ["/"], input.data_source.uri)
}

# Mutable sources require higher privilege
deny["mutable_source_requires_admin"] {
    input.data_source.mutable_policy != "block_on_change"
    not admin_identity
}

admin_identity {
    startswith(input.spiffe_id, "spiffe://poc.local/admin/")
}

# Unregistered external URIs blocked for high-risk sessions
deny["unregistered_high_risk"] {
    input.data_source.registered == false
    input.session.risk_score > 5
}
```

3. Integrate with existing OPA evaluator: when data source verification is triggered (story OC-am3w), populate DataSource field in OPAInput before evaluation.

## Key Files

- POC/internal/gateway/middleware/opa.go (modify -- add DataSourceInput struct and DataSource field to OPAInput)
- POC/config/opa/data_source_policy.rego (create)

## Testing

- Unit tests: OPA policy evaluation for registered source with matching grant (allow), registered source without grant (deny), mutable source by non-admin (deny), unregistered source in high-risk session (deny), unregistered source in low-risk session (allow)
- Integration test: create SPIFFE ID with data source grant, verify it can access registered data source; create SPIFFE ID without grant, verify access denied

## Acceptance Criteria

1. DataSourceInput struct defined with URI, Registered, MutablePolicy, ContentChanged fields
2. OPAInput.DataSource field added (json:"data_source", omitempty)
3. New policy file POC/config/opa/data_source_policy.rego created
4. Policy rules: identity-based access for registered sources, mutable sources require admin, unregistered URIs blocked for high-risk sessions (risk_score > 5)
5. Policy integrated with existing OPA evaluator
6. Unit tests cover all policy evaluation paths
7. Integration test demonstrates identity-based access control for data sources

## Dependencies

Depends on OC-cqj0 (DataSourceDefinition must exist). Relates to OC-am3w (verification middleware populates OPAInput.DataSource).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T01:34:38Z status: in_progress -> closed

## Links
- Parent: [[OC-yrwz]]
- Was blocked by: [[OC-cqj0]]
- Related: [[OC-am3w]]
- Follows: [[OC-cqj0]]
- Led to: [[OC-9aac]]

## Comments
