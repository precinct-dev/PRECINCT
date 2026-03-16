---
id: OC-kd8y
title: "Concession Accumulator and Escalation Detection"
status: closed
priority: 1
type: epic
created_at: 2026-03-08T02:32:36Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:0c02ca15186c8bbfec148ecf84b74c00a49516cc58db1eb0ab901697d9b01366"
labels: [agents-of-chaos, escalation-detection]
closed_at: 2026-03-09T01:32:12Z
close_reason: "All stories accepted"
---

## Description
## Business Context

Case Studies #1 (disproportionate response) and #7 (gaslighting/social pressure) from 'Agents of Chaos' (Shapira et al., 2026, arXiv:2602.20021v1) demonstrate agents making progressively destructive concessions within a single session. Each individual action may score within acceptable risk thresholds; the aggregate is catastrophic (e.g., memory deletion, service shutdown, email account wipe). The paper shows that agents under sustained social pressure or manipulation gradually escalate from benign actions to irreversible destruction without any individual step triggering security controls.

## Problem Being Solved

The session context middleware (step 8, POC/internal/gateway/middleware/session_context.go) already tracks actions chronologically via AgentSession.Actions []ToolAction and computes risk scores, but it does not detect escalation patterns. Step-up gating (step 9, POC/internal/gateway/middleware/step_up_gating.go) evaluates each action independently using RiskDimension (Impact 0-3, Reversibility 0-3, Exposure 0-3, Novelty 0-3) with gates: Fast Path (0-3), Step-Up (4-6), Approval (7-9), Deny (10-12). Neither component detects that a sequence of individually-acceptable actions represents an escalating pattern of destruction.

## Target State

Session context is extended with a 'concession accumulator' that tracks cumulative destructiveness of actions within a session time window. Each action contributes Impact * (4 - Reversibility) to a running escalation score. When the cumulative score crosses configurable thresholds (Warning >= 15, Critical >= 25, Emergency >= 40), the gateway modifies step-up gating behavior: Warning adds a flag, Critical forces step-up on ALL subsequent actions, Emergency denies all non-read actions requiring human intervention.

## Architecture Integration

AgentSession struct (POC/internal/gateway/middleware/session_context.go):
- ID string, SPIFFEID string, StartTime time.Time
- Actions []ToolAction, DataClassifications []string, RiskScore float64, Flags []string

ToolAction struct: Timestamp, Tool, Resource, Classification, ExternalTarget bool, DestinationDomain string

RiskDimension struct (POC/internal/gateway/middleware/step_up_gating.go):
- Impact int (0-3), Reversibility int (0-3), Exposure int (0-3), Novelty int (0-3)
- Total() int returns sum (0-12)

ComputeRiskScore(toolDef *ToolDefinition, session *AgentSession, destination string, isExternal bool, registry *ToolRegistry, allowlist *DestinationAllowlist, defaults UnknownToolDefaults) RiskDimension

DetermineGate(totalScore int, thresholds RiskThresholds) string -- gates: "fast_path", "step_up", "approval", "deny"

RiskThresholds: FastPathMax int (yaml:"fast_path_max"), StepUpMax int (yaml:"step_up_max")

UnknownToolDefaults: Impact 2, Reversibility 2, Exposure 2, Novelty 3 (total 9)

ToolDefinition: Name, Description, Hash, InputSchema, AllowedDestinations, AllowedPaths, RiskLevel string (yaml:"risk_level"), RequiresStepUp bool

KeyDB session store: session:{spiffe_id}:{session_id} -> JSON AgentSession, TTL configurable via SESSION_TTL (default 3600s)

SecurityFlagsCollector with Append(flag string) for upstream flag propagation.

## Acceptance Criteria

1. EscalationScore float64, EscalationHistory []EscalationEvent, and EscalationFlags []string added to AgentSession
2. Escalation scoring formula implemented: each action adds Impact * (4 - Reversibility) to cumulative score
3. Configurable thresholds: Warning >= 15 (flag), Critical >= 25 (force step-up), Emergency >= 40 (deny non-read)
4. Time-window decay: escalation score computed within configurable window (default 1 hour)
5. ComputeRiskScore() modified to incorporate escalation state into risk dimensions
6. Destructive action classification taxonomy implemented and tested
7. E2E demo scenario demonstrating escalation detection with PROOF lines

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T01:32:12Z status: open -> closed

## Links


## Comments
