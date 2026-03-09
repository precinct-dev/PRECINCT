---
id: OC-dz8i
title: "E2E Demo Scenario -- Irreversibility Gating"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, irreversibility]
parent: OC-xbmj
created_at: 2026-03-08T02:44:58Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:04Z
content_hash: "sha256:8bbcfdf7fa7bdcd18dff04b0b5a4f02ad52b786244b2ecbc933959f5b07e030e"
was_blocked_by: [OC-12ng, OC-70gv, OC-h4m7, OC-lmzm, OC-ytph]
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a stakeholder evaluating PRECINCT, I need a demo scenario that demonstrates irreversibility-aware gating so that I can verify PRECINCT treats irreversible actions differently based on the requester's authority level and session escalation state.

## Context

The irreversibility system (stories OC-ytph, OC-h4m7, OC-lmzm) classifies actions into reversibility tiers and modifies step-up gating behavior accordingly. Principal hierarchy (story OC-70gv) provides Level 0-5. Escalation detection (story OC-12ng) provides EscalationScore.

Gateway runs on port 9090 (dev mode) with X-SPIFFE-ID header injection and X-Session-ID for session tracking.

Error codes: stepup_approval_required (step 9, HTTP 403), irreversible_action_denied (step 9, HTTP 403).

## Implementation

Demo scenario:

Step 1: Read-only action by any principal
- X-SPIFFE-ID: spiffe://poc.local/external/bob
- Action: read/list (reversibility=0, Category="reversible")
- Gate: Fast Path (low total score)
- Response: allowed
- PROOF: PROOF S-IRREV-1: Read action (reversible) allowed via fast path

Step 2: File creation by external user
- X-SPIFFE-ID: spiffe://poc.local/external/bob
- Action: create (reversibility=1, Category="costly_reversible")
- Gate: may trigger Step-Up depending on other dimensions
- Response: allowed or step-up (depending on total score)
- PROOF: PROOF S-IRREV-2: Create action (costly_reversible) evaluated appropriately

Step 3: File deletion by owner
- X-SPIFFE-ID: spiffe://poc.local/owner/alice
- Action: delete (reversibility=3, Category="irreversible")
- Principal Level=1 (owner), not forced to Approval
- Gate: Approval (Reversibility=3 raises total score)
- Response includes: X-Precinct-Reversibility: irreversible, X-Precinct-Backup-Recommended: true
- PROOF: PROOF S-IRREV-3: Owner delete (irreversible) gets approval gate with backup recommendation

Step 4: File deletion by external user
- X-SPIFFE-ID: spiffe://poc.local/external/bob
- Action: delete (reversibility=3, Category="irreversible")
- Principal Level=4 (external), forced to Deny for irreversible action by non-owner
- HTTP 403 with "irreversible_action_denied"
- PROOF: PROOF S-IRREV-4: External delete (irreversible) denied

Step 5: Service shutdown by agent in escalated session
- X-SPIFFE-ID: spiffe://poc.local/agents/summarizer/dev
- Previous actions have built EscalationScore > Warning (15)
- Action: shutdown (reversibility=3, Category="irreversible")
- Irreversible + escalated session -> Deny gate
- HTTP 403 with "irreversible_action_denied"
- PROOF: PROOF S-IRREV-5: Irreversible action in escalated session denied

## Key Files

- Demo scripts for irreversibility scenarios
- Makefile demo targets (modify)

## Testing

All 5 PROOF lines must appear in demo output.

## Acceptance Criteria

1. Read action (reversible) fast-pathed (PROOF S-IRREV-1)
2. Create action (costly_reversible) evaluated appropriately (PROOF S-IRREV-2)
3. Owner delete (irreversible) gets approval gate with X-Precinct-Reversibility and X-Precinct-Backup-Recommended headers (PROOF S-IRREV-3)
4. External delete (irreversible) denied with "irreversible_action_denied" (PROOF S-IRREV-4)
5. Irreversible action in escalated session denied (PROOF S-IRREV-5)
6. All 5 PROOF lines produced in make demo-compose output
7. Demo integrated into existing demo framework

## Dependencies

Depends on OC-ytph (classifier), OC-h4m7 (step-up integration), OC-lmzm (backup header), OC-70gv (principal hierarchy), OC-12ng (escalation score).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z dep_removed: was_blocked_by OC-ytph

## Links
- Parent: [[OC-xbmj]]
- Was blocked by: [[OC-12ng]], [[OC-70gv]], [[OC-h4m7]], [[OC-lmzm]], [[OC-ytph]]

## Comments
