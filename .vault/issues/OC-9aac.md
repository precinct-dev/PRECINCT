---
id: OC-9aac
title: "E2E Demo Scenario -- Rug-Pull Detection on External Data"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, data-source-integrity, accepted, delivered]
parent: OC-yrwz
created_at: 2026-03-08T02:39:24Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:9476b7a3b8cab536c2ba7e03d219e1994d56b73ec3f4404559bebeced084b51c"
was_blocked_by: [OC-cqj0, OC-am3w]
follows: [OC-cqj0, OC-am3w, OC-4zrf]
closed_at: 2026-03-09T02:02:22Z
close_reason: "All 5 ACs verified. Integration test with real httptest.Server. Gateway wiring included."
---

## Description
## User Story

As a stakeholder evaluating PRECINCT, I need a demo scenario that demonstrates rug-pull detection on external data sources so that I can verify PRECINCT defends against the mutable resource trust attack documented in Case Study #10 of 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

The demo framework uses make demo-compose with PROOF lines. The data source registry (OC-cqj0) stores DataSourceDefinition with ContentHash (SHA-256, "sha256:" prefix + hex), and the verification middleware (OC-am3w) blocks or flags hash mismatches based on MutablePolicy ("block_on_change", "flag_on_change", "allow"). Error code: "data_source_hash_mismatch" (step 5, HTTP 403).

Gateway runs on port 9090 (dev mode) with X-SPIFFE-ID header injection.

## Implementation

Demo scenario:
1. Register a data source in config/tool-registry.yaml with a known SHA-256 hash:
   ```yaml
   data_sources:
     - uri: "http://mock-external:8080/constitution.txt"
       content_hash: "sha256:<hash-of-original-content>"
       mutable_policy: "block_on_change"
       approved_by: "spiffe://poc.local/admin/security"
   ```
2. Start a mock external HTTP server serving the original content (matching hash)
3. Agent fetches data source through gateway tool call -> allowed (hash matches)
4. Mock server content is mutated (different content, different hash)
5. Agent fetches same data source through gateway tool call -> blocked with "data_source_hash_mismatch" (HTTP 403)
6. Audit trail shows expected vs observed hash

The mock external server can be a simple Go HTTP server in the demo scripts, or a container in the compose stack.

PROOF lines:
- PROOF S-DS-ALLOW: Registered data source with matching hash allowed
- PROOF S-DS-RUGPULL: Mutated data source blocked with hash mismatch
- PROOF S-DS-AUDIT: Audit trail shows expected vs observed hash

## Key Files

- Demo scripts for data source integrity scenarios
- POC/config/tool-registry.yaml (add demo data_sources section)
- Makefile demo targets (modify)

## Testing

All 3 PROOF lines must appear in demo output.

## Acceptance Criteria

1. Registered data source with matching hash allowed through gateway (PROOF S-DS-ALLOW)
2. Mutated data source (different content) blocked with "data_source_hash_mismatch" HTTP 403 (PROOF S-DS-RUGPULL)
3. Audit trail records expected hash, observed hash, and block decision (PROOF S-DS-AUDIT)
4. All PROOF lines produced in make demo-compose output
5. Demo integrated into existing demo framework

## Dependencies

Depends on OC-cqj0 (registry extension), OC-am3w (verification middleware).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T02:02:22Z status: in_progress -> closed

## Links
- Parent: [[OC-yrwz]]
- Was blocked by: [[OC-cqj0]], [[OC-am3w]]
- Follows: [[OC-cqj0]], [[OC-am3w]], [[OC-4zrf]]

## Comments
