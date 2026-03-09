---
id: OC-ytph
title: "Action Reversibility Taxonomy and Classifier"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, irreversibility, delivered]
parent: OC-xbmj
created_at: 2026-03-08T02:43:47Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:05Z
content_hash: "sha256:eb730a7f767b92821807d903da64fbe6c6869c0f4504c8b6062da5987df7a7a7"
was_blocked_by: [OC-pgxd]
follows: [OC-pgxd]
closed_at: 2026-03-08T17:35:05Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security operator, I need an explicit reversibility classifier that analyzes tool actions and parameters to produce a scored reversibility assessment so that step-up gating can make informed decisions about irreversible actions, addressing the lack of consequence awareness documented in Case Studies #1 and #7 of 'Agents of Chaos' (arXiv:2602.20021v1).

## Context

Story OC-pgxd (Epic 3) defines the destructive action classification taxonomy with ClassifyActionDestructiveness(tool, action, params) returning (impact, reversibility). This story builds on the same taxonomy to provide a richer reversibility assessment specifically for step-up gating integration.

RiskDimension (POC/internal/gateway/middleware/step_up_gating.go): Impact int (0-3), Reversibility int (0-3), Exposure int (0-3), Novelty int (0-3).

ToolDefinition: Name, Description, Hash, InputSchema, AllowedDestinations, AllowedPaths, RiskLevel string, RequiresStepUp bool.

The key difference from story OC-pgxd: this classifier produces a structured ActionReversibility object with explanatory metadata (Category label, Explanation, RequiresBackup flag) rather than just numeric scores. It uses the same underlying taxonomy for consistency.

## Implementation

Create POC/internal/gateway/middleware/reversibility.go:

```go
type ActionReversibility struct {
    Score          int    `json:"score"`           // 0=fully reversible, 1=mostly, 2=partially, 3=irreversible
    Category       string `json:"category"`        // "reversible", "costly_reversible", "partially_reversible", "irreversible"
    Explanation    string `json:"explanation"`      // human-readable explanation
    RequiresBackup bool   `json:"requires_backup"` // should pre-action snapshot be taken?
}

func ClassifyReversibility(tool string, action string, params map[string]interface{}, toolDef *ToolDefinition) ActionReversibility
```

Classification rules (consistent with OC-pgxd taxonomy):

**Irreversible (Score=3, Category="irreversible", RequiresBackup=true):**
- Action patterns: "delete", "rm", "remove", "drop", "reset", "wipe", "shutdown", "terminate", "revoke", "purge", "destroy", "truncate"
- Specific cases: email account reset, memory/config file deletion, service shutdown, database drop
- Explanation: "Action cannot be undone. Data/state will be permanently lost."

**Partially reversible (Score=2, Category="partially_reversible", RequiresBackup=true):**
- Action patterns: "modify", "update", "overwrite", "chmod", "chown", "rename", "replace", "patch"
- Specific cases: file content modification (can be undone if backup exists), permission changes
- Explanation: "Action can be reversed if a backup was taken before execution."

**Mostly reversible (Score=1, Category="costly_reversible", RequiresBackup=false):**
- Action patterns: "create", "send", "post", "publish", "write", "insert", "upload"
- Specific cases: message sending (sent but can be deleted on some platforms), file creation
- Explanation: "Action can be reversed with effort. Some side effects may persist."

**Fully reversible (Score=0, Category="reversible", RequiresBackup=false):**
- Action patterns: "read", "list", "search", "get", "health", "status", "ping", "head", "describe", "show", "count", "exists"
- Explanation: "Action is read-only and has no side effects."

Tool registry override: if ToolDefinition is not nil and specifies metadata that implies reversibility, use that as the base. The classifier enhances, not replaces, registry metadata.

## Key Files

- POC/internal/gateway/middleware/reversibility.go (create)

## Testing

- Unit tests: comprehensive classification of action patterns (all four categories), parameter-aware classification (e.g., command param containing "rm"), tool registry override behavior, edge cases (empty action, unknown action)
- Integration test: ClassifyReversibility integrated with existing tool definitions from registry

## Acceptance Criteria

1. ActionReversibility struct with Score (0-3), Category, Explanation, RequiresBackup
2. ClassifyReversibility(tool, action, params, toolDef) function
3. Four classification tiers: irreversible(3), partially_reversible(2), costly_reversible(1), reversible(0)
4. Action pattern matching consistent with OC-pgxd taxonomy
5. RequiresBackup=true for Score >= 2
6. Tool registry metadata override when ToolDefinition is available
7. Human-readable Explanation for each tier
8. Unit tests cover all four tiers, parameter analysis, and registry override

## Dependencies

Depends on OC-pgxd (destructive action classification taxonomy must be defined for consistency).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z dep_removed: no_longer_blocks OC-dz8i

## Links
- Parent: [[OC-xbmj]]
- Was blocked by: [[OC-pgxd]]
- Follows: [[OC-pgxd]]

## Comments
