---
id: OC-d77k
title: "Step-Up Gating Integration with Escalation Score"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, escalation-detection, delivered, accepted]
parent: OC-kd8y
created_at: 2026-03-08T02:40:26Z
created_by: ramirosalas
updated_at: 2026-03-09T00:30:41Z
content_hash: "sha256:8004cd363daafc8959d0a1dbbe624b925d00484e04d00959153ad7302b75c6a3"
was_blocked_by: [OC-12ng, OC-pgxd]
follows: [OC-12ng, OC-pgxd]
closed_at: 2026-03-09T00:30:41Z
close_reason: "Accepted: escalation score integration with step-up gating fully delivered -- applyEscalationOverrides() in ComputeRiskScore() implements Critical(+3 Impact) and Emergency(all dims=3) overrides, RecordActionWithContext() computes and persists escalation contributions, threshold-crossing flags propagate to SecurityFlagsCollector, audit events include escalation_score and escalation_state, 21 tests pass including 2 real integration tests"
led_to: [OC-axk7]
---

## Description
## User Story

As a security operator, I need step-up gating to incorporate the escalation score so that actions which would normally pass the fast path are elevated to step-up or approval when the session shows an escalating pattern of destructive behavior.

## Context

Step-up gating (step 9, POC/internal/gateway/middleware/step_up_gating.go) computes risk scores and determines gates:

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

RiskDimension: Impact int (0-3), Reversibility int (0-3), Exposure int (0-3), Novelty int (0-3). Total() returns sum (0-12).

Gates via DetermineGate(totalScore int, thresholds RiskThresholds): "fast_path" (0-3), "step_up" (4-6), "approval" (7-9), "deny" (10-12).

RiskThresholds: FastPathMax int (yaml:"fast_path_max"), StepUpMax int (yaml:"step_up_max").

Story OC-12ng adds EscalationScore, EscalationFlags to AgentSession. This story makes ComputeRiskScore() and the session context middleware aware of escalation state.

## Implementation

1. In step_up_gating.go ComputeRiskScore():
   - Check session.EscalationScore against thresholds
   - If EscalationScore >= Critical threshold (default 25): add +3 to Impact dimension
     - Effect: actions that would normally score 4-6 (Step-Up) now score 7-9 (Approval required)
     - Effect: actions that would normally be Fast Path (0-3) become Step-Up (4-6)
   - If EscalationScore >= Emergency threshold (default 40): set all dimensions to max (3)
     - Effect: total score = 12, which hits Deny gate for ALL actions

2. In session_context.go RecordAction() (or wherever ToolAction is recorded):
   - After recording the action, compute escalation contribution using story 3.3's classifier
   - Create EscalationEvent with ImpactScore, Reversibility, Contribution (Impact * (4 - Reversibility)), CumulativeAt
   - Update session.EscalationScore
   - Append to session.EscalationHistory
   - If threshold crossed, update session.EscalationFlags and SecurityFlagsCollector.Append()
   - Persist updated session to KeyDB

3. Audit enrichment:
   - Include escalation_score and escalation_state ("normal", "warning", "critical", "emergency") in audit events
   - Include threshold that was crossed (if any)

## Key Files

- POC/internal/gateway/middleware/step_up_gating.go (modify -- ComputeRiskScore)
- POC/internal/gateway/middleware/session_context.go (modify -- RecordAction escalation logic)

## Testing

- Unit tests: ComputeRiskScore with escalation_score=0 (no change), with escalation_score=25 (Critical: +3 Impact), with escalation_score=40 (Emergency: all max). Verify gate transitions: fast_path action becomes step_up at Critical, everything becomes deny at Emergency.
- Integration test: sequence of destructive actions (accumulating escalation score past Critical threshold), then a normally-fast-path action is elevated to step-up gate

## Acceptance Criteria

1. ComputeRiskScore() checks session.EscalationScore against thresholds
2. EscalationScore >= Critical (25): +3 added to Impact dimension
3. EscalationScore >= Emergency (40): all RiskDimension values set to 3 (deny gate)
4. RecordAction() computes escalation contribution and updates session.EscalationScore
5. EscalationEvent created and appended to session.EscalationHistory
6. Threshold crossing triggers SecurityFlagsCollector.Append() and session.EscalationFlags update
7. Audit events include escalation_score and escalation_state
8. Unit tests verify gate transitions at each threshold
9. Integration test demonstrates escalation affecting real gate decisions

## Dependencies

Depends on OC-12ng (escalation score tracking must exist in AgentSession).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T00:30:41Z dep_removed: no_longer_blocks OC-axk7

## Links
- Parent: [[OC-kd8y]]
- Was blocked by: [[OC-12ng]], [[OC-pgxd]]
- Follows: [[OC-12ng]], [[OC-pgxd]]
- Led to: [[OC-axk7]]

## Comments
