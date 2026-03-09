---
id: OC-h4m7
title: "Automatic Step-Up for Irreversible Actions"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, irreversibility]
parent: OC-xbmj
created_at: 2026-03-08T02:44:14Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:04Z
content_hash: "sha256:4753c638b1e1a687f45c925434f67cd8d69247b89040fbb6e91914696fe0ff5e"
was_blocked_by: [OC-12ng, OC-70gv, OC-ytph]
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security operator, I need step-up gating to automatically escalate the gate for irreversible actions based on the requester's principal level and session escalation state so that non-owner principals cannot perform irreversible actions without approval, and escalated sessions are denied irreversible actions entirely.

## Context

Story OC-ytph provides ClassifyReversibility(tool, action, params, toolDef) returning ActionReversibility with Score (0-3). Story OC-70gv provides PrincipalRole with Level (0-5). Story OC-12ng provides EscalationScore in AgentSession.

ComputeRiskScore (POC/internal/gateway/middleware/step_up_gating.go):
```go
func ComputeRiskScore(
    toolDef *ToolDefinition,
    session *AgentSession,
    destination string,
    isExternal bool,
    registry *ToolRegistry,
    allowlist *DestinationAllowlist,
    defaults UnknownToolDefaults,
) RiskDimension
```

RiskDimension: Impact (0-3), Reversibility (0-3), Exposure (0-3), Novelty (0-3). Total() = sum (0-12).

DetermineGate(totalScore, thresholds): "fast_path" (0-3), "step_up" (4-6), "approval" (7-9), "deny" (10-12).

Escalation thresholds: Warning >= 15, Critical >= 25, Emergency >= 40.

## Implementation

Modify ComputeRiskScore() in step_up_gating.go:

1. Call ClassifyReversibility(tool, action, params, toolDef) to get ActionReversibility
2. If ActionReversibility.Score >= 2 (partially reversible or worse):
   - Override RiskDimension.Reversibility with ActionReversibility.Score
   - This replaces the generic reversibility score from tool registry metadata
3. If ActionReversibility.Score == 3 (irreversible) AND principal_level > 1 (not owner):
   - Force Approval gate: set RiskDimension to ensure Total() >= 7 (approval range)
   - Specifically: if current total < 7, add enough to Impact to reach 7
4. If ActionReversibility.Score == 3 AND session.EscalationScore > Warning threshold (15):
   - Force Deny gate: set RiskDimension to ensure Total() >= 10 (deny range)
   - This is the most restrictive: irreversible action + escalated session = denied

Add reversibility header to proxied request:
- X-Precinct-Reversibility: "irreversible" | "partially_reversible" | "costly_reversible" | "reversible"
- Injected alongside the existing principal headers

Include reversibility classification in audit events.

New error code: "irreversible_action_denied" (step 9, HTTP 403, middleware "step_up_gating")

## Key Files

- POC/internal/gateway/middleware/step_up_gating.go (modify -- ComputeRiskScore)
- POC/internal/gateway/middleware/error_codes.go (modify -- add irreversible_action_denied)

## Testing

- Unit tests: irreversible action by owner (Level=1) with no escalation -> approval gate (Score=3 overrides Reversibility, but owner not forced), irreversible action by external (Level=4) -> approval gate forced, irreversible action by external in escalated session (EscalationScore > 15) -> deny gate forced, reversible action unaffected by classifier
- Integration test: sequence showing reversibility affecting gate decisions: external user attempts delete -> approval required; external user in escalated session attempts delete -> denied

## Acceptance Criteria

1. ClassifyReversibility() called within ComputeRiskScore()
2. ActionReversibility.Score >= 2 overrides RiskDimension.Reversibility
3. Irreversible (Score=3) by non-owner (Level > 1) forces Approval gate (Total >= 7)
4. Irreversible (Score=3) in escalated session (EscalationScore > Warning) forces Deny gate (Total >= 10)
5. X-Precinct-Reversibility header injected into proxied requests
6. New error code "irreversible_action_denied" added
7. Audit events include reversibility classification
8. Unit tests verify all gate escalation scenarios
9. Integration test demonstrates reversibility affecting real gate decisions

## Dependencies

Depends on OC-ytph (reversibility classifier), OC-70gv (principal role), OC-12ng (escalation score).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z dep_removed: was_blocked_by OC-ytph

## Links
- Parent: [[OC-xbmj]]
- Was blocked by: [[OC-12ng]], [[OC-70gv]], [[OC-ytph]]

## Comments
