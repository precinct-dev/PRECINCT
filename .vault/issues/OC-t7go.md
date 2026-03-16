---
id: OC-t7go
title: "Request Enrichment with Principal Metadata Headers"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, principal-hierarchy]
parent: OC-qkal
created_at: 2026-03-08T02:42:27Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:b5a0c2f69ff095a6c7451939166d39f6ceff923347f12c5228766d531acec90d"
was_blocked_by: [OC-70gv]
closed_at: 2026-03-08T17:35:05Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security operator, I need the gateway to inject principal role metadata headers into proxied requests so that downstream agent frameworks can read structured authority information and weight instructions accordingly, addressing the fundamental 'who do I serve?' confusion documented in 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

Story OC-70gv defines PrincipalRole with Level (0-5), Role, Capabilities, TrustDomain, AuthMethod and the ResolvePrincipalRole() function. This story adds header injection into the proxied request.

SPIFFE Auth (step 3) validates identity and stores the SPIFFE ID in request context. OPA policy (step 6) evaluates authorization. Principal resolution runs after both steps.

Existing header patterns in api-reference.md:
- X-SPIFFE-ID: set by client in dev mode, extracted from mTLS cert in prod mode
- X-Session-ID: set by client for session correlation

The gateway already strips and re-computes certain headers for security (e.g., SPIFFE ID in prod mode is never taken from a client header). The principal headers must follow the same pattern: strip any client-provided values, then inject gateway-computed values.

AuditEvent: Timestamp, EventType, Severity, SessionID, DecisionID, TraceID, SPIFFEID, Action, Result.

## Implementation

Add principal resolution and header injection to the middleware chain. This runs after SPIFFE auth (step 3) and can be integrated as a lightweight middleware or as part of the existing SPIFFE auth middleware:

1. Strip any client-provided principal headers from the inbound request:
   - Delete: X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, X-Precinct-Auth-Method
   - This prevents clients from forging authority headers

2. After SPIFFE auth completes and SPIFFE ID is in context:
   - Call ResolvePrincipalRole(spiffeID, trustDomain, authMethod)
   - Inject headers into the request before proxying:
     - X-Precinct-Principal-Level: <int> (e.g., "4")
     - X-Precinct-Principal-Role: <string> (e.g., "external_user")
     - X-Precinct-Principal-Capabilities: <comma-separated> (e.g., "read")
     - X-Precinct-Auth-Method: <string> (e.g., "mtls_svid" or "header_declared")

3. Store PrincipalRole in request context (same pattern as SPIFFE ID storage) for downstream middleware to read.

4. Enrich audit events: add principal_level and principal_role to AuditEvent (or its Security sub-struct).

## Key Files

- POC/internal/gateway/middleware/spiffe_auth.go (modify -- add header stripping and injection, or create separate principal middleware)
- POC/internal/gateway/middleware/audit.go (modify -- add principal role to audit events)

## Testing

- Unit tests: header injection (correct values for each principal level), header stripping (client-provided X-Precinct-Principal-Level is removed and re-computed), audit event enrichment with principal role
- Integration test: request from owner SPIFFE ID (spiffe://poc.local/owner/alice) gets X-Precinct-Principal-Level: 1; request from external SPIFFE ID (spiffe://poc.local/external/bob) gets X-Precinct-Principal-Level: 4

## Acceptance Criteria

1. Client-provided X-Precinct-Principal-* headers stripped from inbound requests (anti-forgery)
2. X-Precinct-Principal-Level header injected with numeric authority level (0-5)
3. X-Precinct-Principal-Role header injected with role string
4. X-Precinct-Principal-Capabilities header injected with comma-separated capabilities
5. X-Precinct-Auth-Method header injected with authentication method
6. PrincipalRole stored in request context for downstream middleware access
7. Audit events include principal_level and principal_role
8. Unit tests verify header injection, stripping, and audit enrichment
9. Integration test verifies different SPIFFE IDs produce correct principal levels

## Dependencies

Depends on OC-70gv (PrincipalRole struct and ResolvePrincipalRole function must exist).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z dep_removed: no_longer_blocks OC-f0xy

## Links
- Parent: [[OC-qkal]]
- Was blocked by: [[OC-70gv]]

## Comments
