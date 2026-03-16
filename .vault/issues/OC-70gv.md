---
id: OC-70gv
title: "Principal Role Resolution from SPIFFE Identity"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, principal-hierarchy]
parent: OC-qkal
created_at: 2026-03-08T02:42:00Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:f5ce2fcee5934545035f0d61a8f4f4e4a4e88771e3918461980448eed9baf749"
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security operator, I need the gateway to resolve SPIFFE IDs to principal roles with defined authority levels so that downstream systems can make authority-aware decisions, addressing the fundamental confusion between owner and non-owner instructions documented across multiple case studies in 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

SPIFFE Auth (step 3, POC/internal/gateway/middleware/spiffe_auth.go) extracts SPIFFE IDs from X-SPIFFE-ID header (dev mode) or mTLS cert URI SAN (prod mode). Trust domain: poc.local (Compose) or agentic-ref-arch.poc (K8s). The SPIFFE ID is available in the request context after step 3.

OPA policy (step 6) already evaluates authorization using the SPIFFE ID. This story adds a parallel resolution that maps SPIFFE ID patterns to principal roles.

Config: SPIFFETrustDomain string (default "poc.local"), OPAPolicyDir string.

Existing OPA policies: POC/config/opa/mcp_policy.rego, ui_policy.rego, exfiltration.rego, context_policy.rego, ui_csp_policy.rego.

## Implementation

Create POC/internal/gateway/middleware/principal.go:

```go
type PrincipalRole struct {
    Level        int      `json:"level"`        // 0=system, 1=owner, 2=delegated, 3=peer_agent, 4=external, 5=anonymous
    Role         string   `json:"role"`         // "system", "owner", "delegated_admin", "agent", "external_user", "anonymous"
    Capabilities []string `json:"capabilities"` // ["admin", "read", "write", "execute", "delegate"]
    TrustDomain  string   `json:"trust_domain"` // SPIFFE trust domain
    AuthMethod   string   `json:"auth_method"`  // "mtls_svid", "token", "header_declared"
}
```

Principal hierarchy (Level 0 = highest authority):
- Level 0 (system): SPIFFE IDs starting with spiffe://{trust_domain}/system/ -- internal gateway processes
- Level 1 (owner): SPIFFE IDs starting with spiffe://{trust_domain}/owner/ -- the human or entity that owns the agent
- Level 2 (delegated): SPIFFE IDs starting with spiffe://{trust_domain}/delegated/ -- delegated administrators
- Level 3 (peer_agent): SPIFFE IDs starting with spiffe://{trust_domain}/agents/ -- peer agents in the system
- Level 4 (external): SPIFFE IDs starting with spiffe://{trust_domain}/external/ -- external users or services
- Level 5 (anonymous): no valid SPIFFE ID or unresolvable identity

Resolution function:
```go
func ResolvePrincipalRole(spiffeID string, trustDomain string, authMethod string) PrincipalRole
```

Resolution logic:
1. Parse SPIFFE ID URI: spiffe://{trust_domain}/{path_prefix}/...
2. Match path prefix against hierarchy (system/, owner/, delegated/, agents/, external/)
3. Determine capabilities based on level
4. If no match: Level=5 (anonymous) with empty capabilities

Create OPA policy file POC/config/opa/principal_policy.rego:
```rego
package precinct.principal

principal_role := "system" { startswith(input.spiffe_id, concat("/", ["spiffe:/", input.trust_domain, "system/"])) }
principal_role := "owner" { startswith(input.spiffe_id, concat("/", ["spiffe:/", input.trust_domain, "owner/"])) }
principal_role := "delegated_admin" { startswith(input.spiffe_id, concat("/", ["spiffe:/", input.trust_domain, "delegated/"])) }
principal_role := "agent" { startswith(input.spiffe_id, concat("/", ["spiffe:/", input.trust_domain, "agents/"])) }
principal_role := "external_user" { startswith(input.spiffe_id, concat("/", ["spiffe:/", input.trust_domain, "external/"])) }
principal_role := "anonymous" { not principal_known }
principal_known { startswith(input.spiffe_id, "spiffe://") }
```

## Key Files

- POC/internal/gateway/middleware/principal.go (create)
- POC/config/opa/principal_policy.rego (create)

## Testing

- Unit tests: SPIFFE ID to role mapping for each level (system, owner, delegated, agent, external, anonymous), capability resolution per level, trust domain extraction, auth method passthrough
- Integration test: SPIFFE ID with agents/ prefix resolves to Level=3 Role="agent" with correct capabilities

## Acceptance Criteria

1. PrincipalRole struct with Level (0-5), Role, Capabilities, TrustDomain, AuthMethod
2. ResolvePrincipalRole() maps SPIFFE ID path prefix to hierarchy level
3. Six hierarchy levels: system(0), owner(1), delegated(2), peer_agent(3), external(4), anonymous(5)
4. Capabilities determined per level: owner gets ["admin","read","write","execute","delegate"], external gets ["read"]
5. principal_policy.rego created with matching OPA rules
6. Unresolvable SPIFFE IDs default to Level=5 (anonymous) with empty capabilities
7. Auth method preserved: "mtls_svid" for prod mode, "header_declared" for dev mode
8. Unit tests cover all 6 levels plus edge cases (empty SPIFFE ID, wrong trust domain)

## Scope Boundary

This story defines the resolution function and OPA policy. Header injection is story 4.2. Extended authorization policies are story 4.3.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z dep_removed: no_longer_blocks OC-dz8i

## Links
- Parent: [[OC-qkal]]

## Comments
