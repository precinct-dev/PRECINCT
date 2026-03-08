---
id: OC-f0xy
title: "E2E Demo Scenario -- Principal Hierarchy Enforcement"
status: open
priority: 2
type: task
labels: [agents-of-chaos, principal-hierarchy]
parent: OC-qkal
created_at: 2026-03-08T02:43:12Z
created_by: ramirosalas
updated_at: 2026-03-08T02:43:12Z
content_hash: "sha256:8e10451771562a7c3f97824ccdec04cf61b8efc2eceba2417d7e280fe9dbf4f8"
blocked_by: [OC-70gv, OC-t7go, OC-3ch6]
---

## Description
## User Story

As a stakeholder evaluating PRECINCT, I need a demo scenario that demonstrates principal hierarchy enforcement so that I can verify PRECINCT distinguishes between owner and non-owner authority levels as documented in 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

The principal hierarchy system (stories OC-70gv, OC-t7go, OC-3ch6) resolves SPIFFE IDs to authority levels and enforces level-based access control. Levels: system(0), owner(1), delegated(2), peer_agent(3), external(4), anonymous(5).

Gateway runs on port 9090 (dev mode) with X-SPIFFE-ID header injection. In dev mode, the principal level is determined from the X-SPIFFE-ID path prefix.

Error code: "principal_level_insufficient" (step 6, HTTP 403).

## Implementation

Demo scenario:

Step 1: Owner identity calls destructive tool
- X-SPIFFE-ID: spiffe://poc.local/owner/alice
- Tool: file management, Action: delete
- Principal resolution: Level=1 (owner)
- OPA rule: destructive requires level <= 2, owner is level 1 -> allowed
- Response headers include: X-Precinct-Principal-Level: 1, X-Precinct-Principal-Role: owner
- PROOF: PROOF S-PRINCIPAL-1: Owner (level 1) allowed destructive operation

Step 2: External identity calls same destructive tool
- X-SPIFFE-ID: spiffe://poc.local/external/bob
- Tool: file management, Action: delete
- Principal resolution: Level=4 (external_user)
- OPA rule: destructive requires level <= 2, external is level 4 -> denied
- HTTP 403 with "principal_level_insufficient"
- PROOF: PROOF S-PRINCIPAL-2: External (level 4) denied destructive operation

Step 3: Agent identity calls inter-agent messaging
- X-SPIFFE-ID: spiffe://poc.local/agents/summarizer/dev
- Tool: messaging_send
- Principal resolution: Level=3 (agent)
- OPA rule: messaging requires level <= 3, agent is level 3 -> allowed
- PROOF: PROOF S-PRINCIPAL-3: Agent (level 3) allowed inter-agent messaging

Step 4: External identity calls inter-agent messaging
- X-SPIFFE-ID: spiffe://poc.local/external/bob
- Tool: messaging_send
- Principal resolution: Level=4 (external_user)
- OPA rule: messaging requires level <= 3, external is level 4 -> denied
- PROOF: PROOF S-PRINCIPAL-4: External (level 4) denied inter-agent messaging

## Key Files

- Demo scripts for principal hierarchy scenarios
- Makefile demo targets (modify)

## Testing

All 4 PROOF lines must appear in demo output.

## Acceptance Criteria

1. Owner (level 1) allowed destructive operation, response includes X-Precinct-Principal-Level: 1 (PROOF S-PRINCIPAL-1)
2. External (level 4) denied destructive operation with "principal_level_insufficient" (PROOF S-PRINCIPAL-2)
3. Agent (level 3) allowed inter-agent messaging (PROOF S-PRINCIPAL-3)
4. External (level 4) denied inter-agent messaging (PROOF S-PRINCIPAL-4)
5. All 4 PROOF lines produced in make demo-compose output
6. Demo integrated into existing demo framework

## Dependencies

Depends on OC-70gv (principal resolution), OC-t7go (header injection), OC-3ch6 (principal-aware OPA policies).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:43:16Z dep_added: blocked_by OC-3ch6

## Links
- Parent: [[OC-qkal]]
- Blocked by: [[OC-70gv]], [[OC-t7go]], [[OC-3ch6]]

## Comments
