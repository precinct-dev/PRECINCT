---
id: OC-am3w
title: "Data Source Verification Middleware Logic"
status: in_progress
priority: 1
type: task
labels: [agents-of-chaos, data-source-integrity, delivered]
parent: OC-yrwz
created_at: 2026-03-08T02:38:37Z
created_by: ramirosalas
updated_at: 2026-03-09T00:34:18Z
content_hash: "sha256:c5a1117011ebf83716b5721f81cf6ed2884d7e805adf3603d4d47f5ce4a2d5e6"
blocked_by: [OC-cqj0]
related: [OC-4zrf]
blocks: [OC-9aac]
---

## Description
## User Story

As a security operator, I need the gateway to verify external data source content hashes when agents fetch them so that mutated data sources (rug-pull attacks, Case Study #10) are detected and blocked or flagged based on the configured mutable policy.

## Context

Story OC-cqj0 adds DataSourceDefinition to the tool registry. This story adds the verification logic that runs when an agent's tool call references an external data source. The verification integrates with the existing tool registry verification flow in VerifyToolRequest() (step 5).

Existing tool registry verification (tool_registry.go): VerifyToolRequest() checks tool hash, detects rug-pull (hash mismatch on registered tool). Returns allow/deny with reason.

SecurityFlagsCollector (POC/internal/gateway/middleware/context.go): Append(flag string) for flag propagation to upstream middleware (audit, step-up gating).

AuditEvent (POC/internal/gateway/middleware/audit.go): Timestamp, EventType, Severity, SessionID, DecisionID, TraceID, SPIFFEID, Action, Result.

Existing error codes (api-reference.md): registry_hash_mismatch (step 5, HTTP 403), registry_tool_unknown (step 5, HTTP 403).

## Implementation

In POC/internal/gateway/middleware/tool_registry.go, extend VerifyToolRequest() or add a parallel VerifyDataSource() method:

1. When a tool call includes a URL parameter (or the request references an external resource via a recognized attribute like "source_url" or "data_uri"):
   a. Extract the URL from tool call parameters
   b. Look up URL in data source registry: GetDataSource(uri)

2. If registered:
   a. Check if RefreshTTL has elapsed since LastVerified
   b. If TTL elapsed or first verification: fetch content from URI, compute SHA-256
   c. Compare computed hash to DataSourceDefinition.ContentHash
   d. If match: allow, update LastVerified timestamp
   e. If mismatch, apply MutablePolicy:
      - "block_on_change": return deny with new error code "data_source_hash_mismatch" (HTTP 403)
      - "flag_on_change": SecurityFlagsCollector.Append("data_source_hash_mismatch"), allow but flagged
      - "allow": allow silently (but still log audit event)
   f. Emit audit event with URI, expected hash, observed hash, policy applied

3. If not registered:
   a. Apply configurable UnknownDataSourcePolicy (new config field, default: "flag"):
      - "flag": SecurityFlagsCollector.Append("unregistered_data_source"), allow
      - "block": return deny with new error code "unregistered_data_source" (HTTP 403)
      - "allow": allow silently
   b. Emit audit event

New error codes to add to error_codes.go:
- "data_source_hash_mismatch" (step 5, HTTP 403, middleware "tool_registry_verify")
- "unregistered_data_source" (step 5, HTTP 403, middleware "tool_registry_verify")

New config field in Config struct:
- UnknownDataSourcePolicy string (env: UNKNOWN_DATA_SOURCE_POLICY, default: "flag")

## Key Files

- POC/internal/gateway/middleware/tool_registry.go (modify -- add verification logic)
- POC/internal/gateway/middleware/error_codes.go (modify -- add new error codes)
- POC/internal/gateway/config.go (modify -- add UnknownDataSourcePolicy)

## Testing

- Unit tests: hash match (allow), hash mismatch with block_on_change (deny), hash mismatch with flag_on_change (flag added to SecurityFlagsCollector, allow), unregistered source with flag policy (flagged), unregistered source with block policy (denied), expired RefreshTTL triggers re-verification
- Integration test: register data source with known hash, simulate content mutation (return different content), verify gateway blocks with "data_source_hash_mismatch"

## Acceptance Criteria

1. Data source URI extracted from tool call parameters
2. Registered data sources: content fetched and SHA-256 hash computed
3. Hash match: allow and update LastVerified
4. Hash mismatch: apply MutablePolicy (block_on_change -> deny, flag_on_change -> flag, allow -> pass)
5. Unregistered sources: apply UnknownDataSourcePolicy (default: "flag")
6. New error codes: "data_source_hash_mismatch" and "unregistered_data_source" added to error_codes.go
7. SecurityFlagsCollector.Append() used for flag propagation
8. Audit events emitted with URI, expected hash, observed hash
9. RefreshTTL respected -- no re-fetch within TTL window
10. Unit tests cover all policy combinations
11. Integration test demonstrates rug-pull detection

## Dependencies

Depends on OC-cqj0 (DataSourceDefinition must exist in registry).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: VerifyDataSource implementation with hash comparison, mutable policy (block_on_change/flag_on_change/allow), RefreshTTL caching, unknown source policy, middleware wiring, error codes, config env var. 11 unit tests + 4 integration tests all passing. Pre-existing gateway test failures (TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey, TestMCPTransportHTTPClient_StrictRequiresSPIFFETLS) unrelated to this change.

## History
- 2026-03-09T00:34:18Z status: in_progress -> in_progress

## Links
- Parent: [[OC-yrwz]]
- Blocks: [[OC-9aac]]
- Blocked by: [[OC-cqj0]]
- Related: [[OC-4zrf]]

## Comments
