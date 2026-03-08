---
id: OC-12ng
title: "Escalation Score Tracking in Session Context"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, escalation-detection, delivered, accepted]
parent: OC-kd8y
created_at: 2026-03-08T02:40:01Z
created_by: ramirosalas
updated_at: 2026-03-08T03:45:08Z
content_hash: "sha256:ad996489fc93bd4775b1e8493cd0aff8a46fac12d2360a6a78d829067d14b0b2"
closed_at: 2026-03-08T03:45:08Z
close_reason: "Accepted: Escalation score tracking with time-window decay, all 3 threshold flags, and SecurityFlagsCollector propagation wired into session middleware. 11 tests executed (8 unit + 2 serialization + 1 middleware integration), all pass."
led_to: [OC-d77k]
---

## Description
## User Story

As a security operator, I need the session context to track cumulative destructiveness of actions within a session so that gradually escalating patterns of destruction (Case Studies #1 and #7 of 'Agents of Chaos', arXiv:2602.20021v1) are detected even when each individual action scores within acceptable risk thresholds.

## Context

The session context middleware (step 8, POC/internal/gateway/middleware/session_context.go) manages AgentSession:
```go
type AgentSession struct {
    ID                  string
    SPIFFEID            string
    StartTime           time.Time
    Actions             []ToolAction
    DataClassifications []string
    RiskScore           float64
    Flags               []string
}
```

ToolAction: Timestamp time.Time, Tool string, Resource string, Classification string, ExternalTarget bool, DestinationDomain string.

Sessions are stored in KeyDB: session:{spiffe_id}:{session_id} -> JSON AgentSession, session:{spiffe_id}:{session_id}:actions -> LIST of ToolAction. TTL: SESSION_TTL (default 3600s, env: SESSION_TTL).

SecurityFlagsCollector (POC/internal/gateway/middleware/context.go): Flags []string, Append(flag string).

RiskDimension (step_up_gating.go): Impact int (0-3), Reversibility int (0-3), Exposure int (0-3), Novelty int (0-3).

## Implementation

Extend AgentSession in session_context.go:

```go
type AgentSession struct {
    ID                  string
    SPIFFEID            string
    StartTime           time.Time
    Actions             []ToolAction
    DataClassifications []string
    RiskScore           float64
    Flags               []string
    EscalationScore     float64            // cumulative destructiveness
    EscalationHistory   []EscalationEvent  // chronological record
    EscalationFlags     []string           // "escalation_warning", "escalation_critical", "escalation_emergency"
}

type EscalationEvent struct {
    Timestamp     time.Time `json:"timestamp"`
    Tool          string    `json:"tool"`
    Action        string    `json:"action"`
    ImpactScore   float64   `json:"impact_score"`      // from step-up gating Impact dimension
    Reversibility float64   `json:"reversibility"`     // from step-up gating Reversibility dimension
    Contribution  float64   `json:"contribution"`      // Impact * (4 - Reversibility)
    CumulativeAt  float64   `json:"cumulative_at"`     // running total at this point
}
```

Escalation scoring formula: each action adds Impact * (4 - Reversibility) to cumulative score:
- Read-only (Impact=0, Reversibility=0): 0 * 4 = 0
- Low destructive (Impact=1, Reversibility=1): 1 * 3 = 3
- Medium destructive (Impact=2, Reversibility=2): 2 * 2 = 4
- High destructive (Impact=3, Reversibility=3): 3 * 1 = 3
- Irreversible destructive (Impact=3, Reversibility=0): 3 * 4 = 12

Configurable thresholds (new config fields or in risk_thresholds.yaml):
- EscalationWarningThreshold: float64 (default 15) -- adds "escalation_warning" flag
- EscalationCriticalThreshold: float64 (default 25) -- forces step-up on ALL subsequent actions
- EscalationEmergencyThreshold: float64 (default 40) -- denies all non-read actions

Time-window decay: only count actions within configurable window (default 1 hour, same as SESSION_TTL). Actions older than the window do not contribute to EscalationScore.

Store EscalationScore, EscalationHistory, EscalationFlags in KeyDB session (same JSON serialization pattern as existing AgentSession fields).

When thresholds are crossed:
- Warning: SecurityFlagsCollector.Append("escalation_warning")
- Critical: SecurityFlagsCollector.Append("escalation_critical")
- Emergency: SecurityFlagsCollector.Append("escalation_emergency")

## Key Files

- POC/internal/gateway/middleware/session_context.go (modify)
- POC/config/risk_thresholds.yaml (modify -- add escalation thresholds)

## Testing

- Unit tests: escalation score computation for various Impact/Reversibility combinations, threshold transitions (below warning, at warning, at critical, at emergency), time-window decay (old actions excluded), flag propagation via SecurityFlagsCollector
- Integration test: sequence of actions that crosses warning threshold, verify "escalation_warning" flag in SecurityFlagsCollector

## Acceptance Criteria

1. EscalationScore float64 added to AgentSession
2. EscalationHistory []EscalationEvent added with Timestamp, Tool, Action, ImpactScore, Reversibility, Contribution, CumulativeAt
3. EscalationFlags []string added to AgentSession
4. Escalation scoring: Impact * (4 - Reversibility) per action
5. Configurable thresholds: Warning >= 15, Critical >= 25, Emergency >= 40
6. Time-window decay: only actions within configurable window (default 1 hour) counted
7. Threshold crossing adds flags to SecurityFlagsCollector: "escalation_warning", "escalation_critical", "escalation_emergency"
8. Escalation data persisted in KeyDB session store
9. Unit tests cover score computation, threshold transitions, and time-window decay
10. Integration test verifies flag propagation on threshold crossing

## Scope Boundary

This story adds score tracking and flag propagation ONLY. Integration with step-up gating is story 3.2. Destructive action classification taxonomy is story 3.3.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T03:45:08Z dep_removed: no_longer_blocks OC-dz8i

## Links
- Parent: [[OC-kd8y]]
- Led to: [[OC-d77k]]

## Comments
