---
id: OC-xbmj
title: "Irreversibility Classification and Gating"
status: closed
priority: 2
type: epic
created_at: 2026-03-08T02:33:25Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:5550fcdfceb2ca3f1d7876c566ea726732e635f84524cc5c29944ea6c2502788"
labels: [agents-of-chaos, irreversibility]
closed_at: 2026-03-08T17:35:05Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## Business Context

Case Studies #1 (disproportionate response -- agent deletes emails instead of summarizing) and #7 (gaslighting -- agent progressively deletes memory, shuts down services) from 'Agents of Chaos' (Shapira et al., 2026, arXiv:2602.20021v1) demonstrate agents taking irreversible actions without recognizing their irreversibility. The agents treat 'delete all emails' and 'list emails' as equivalent operations because nothing in their processing pipeline distinguishes the consequences.

## Problem Being Solved

Step-up gating (step 9) already has a Reversibility dimension (0-3) in RiskDimension, but it is computed generically from tool registry metadata (RiskLevel, RequiresStepUp). There is no explicit, automatic classification based on action semantics. A tool registered as 'medium' risk with no RequiresStepUp=true will get a generic reversibility score even if the specific action (e.g., 'rm -rf /') is catastrophically irreversible.

## Target State

A ReversibilityClassifier analyzes tool name + action + parameters to produce an explicit ActionReversibility score (0-3) with category labels. Step-up gating uses this classification to override generic reversibility scores. Irreversible actions (Score=3) by non-owner principals force the Approval gate. Irreversible actions in escalated sessions (escalation_score > Warning) force the Deny gate. A backup recommendation header signals to agent frameworks that pre-action state preservation is advisable.

## Architecture Integration

RiskDimension struct (POC/internal/gateway/middleware/step_up_gating.go):
- Impact int (0-3), Reversibility int (0-3), Exposure int (0-3), Novelty int (0-3)
- Total() int returns sum (0-12)

ComputeRiskScore(toolDef *ToolDefinition, session *AgentSession, destination string, isExternal bool, registry *ToolRegistry, allowlist *DestinationAllowlist, defaults UnknownToolDefaults) RiskDimension

DetermineGate(totalScore int, thresholds RiskThresholds): "fast_path" (0-3), "step_up" (4-6), "approval" (7-9), "deny" (10-12)

ToolDefinition fields: Name, Description, Hash, InputSchema, AllowedDestinations, AllowedPaths, RiskLevel string, RequiresStepUp bool, RequiredScope string

UnknownToolDefaults: Impact=2, Reversibility=2, Exposure=2, Novelty=3

Depends on Epic 3 (OC-kd8y) story 3.3 for consistent destructive action taxonomy. The reversibility classifier and the destructive action classifier must use the same underlying taxonomy to avoid divergent classifications.

## Acceptance Criteria

1. ActionReversibility struct with Score (0-3), Category, Explanation, RequiresBackup
2. ReversibilityClassifier classifies tool+action+params into reversibility scores
3. Step-up gating overrides generic Reversibility dimension with classifier output
4. Irreversible actions by non-owner principals force Approval gate
5. Irreversible actions in escalated sessions force Deny gate
6. X-Precinct-Reversibility and X-Precinct-Backup-Recommended headers on proxied requests
7. E2E demo scenario demonstrating irreversibility gating with PROOF lines

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z status: open -> closed

## Links


## Comments
