---
id: OC-pgxd
title: "Destructive Action Classification Taxonomy"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, escalation-detection, delivered, accepted]
parent: OC-kd8y
created_at: 2026-03-08T02:40:57Z
created_by: ramirosalas
updated_at: 2026-03-08T03:52:44Z
content_hash: "sha256:e5d7e52d65b76c17598261b457f348fb69e087e5b96d4aadceb032dda7ba2ac1"
closed_at: 2026-03-08T03:52:44Z
close_reason: "Accepted: Destructive action classification taxonomy with four-tier model, parameter analysis, and registry override semantics. 34 unit tests pass, full middleware suite clean."
led_to: [OC-d77k, OC-ytph]
---

## Description
## User Story

As a security operator, I need a classification taxonomy that automatically determines the destructiveness and reversibility of tool actions based on their semantics so that the escalation accumulator (OC-12ng) and step-up gating integration (OC-d77k) have accurate input values, and the irreversibility classifier (Epic OC-xbmj) uses a consistent taxonomy.

## Context

Step-up gating currently determines Impact and Reversibility from ToolDefinition metadata (RiskLevel string: "low", "medium", "high", "critical"; RequiresStepUp bool). This is static per-tool and does not consider the specific action or parameters. For example, a file management tool has the same risk score whether the action is "read" or "delete".

ToolDefinition (POC/internal/gateway/middleware/tool_registry.go): Name, Description, Hash, InputSchema, AllowedDestinations, AllowedPaths, RiskLevel string (yaml:"risk_level"), RequiresStepUp bool, RequiredScope string.

UnknownToolDefaults (step_up_gating.go): Impact=2, Reversibility=2, Exposure=2, Novelty=3.

The escalation scoring formula (story OC-12ng) is: Impact * (4 - Reversibility). This story provides the Impact and Reversibility values per action.

## Implementation

Add ClassifyActionDestructiveness function to session_context.go (or a new file if cleaner):

```go
func ClassifyActionDestructiveness(tool string, action string, params map[string]interface{}) (impact float64, reversibility float64) {
    // ... classification logic
}
```

Classification taxonomy (action pattern -> Impact, Reversibility):

**Critical destructive** (Impact=3, Reversibility=3 meaning irreversible):
- Action patterns: "delete", "rm", "remove", "drop", "reset", "wipe", "shutdown", "terminate", "revoke", "purge", "destroy", "truncate"
- Example: rm -rf, DROP TABLE, account reset, memory purge, service shutdown

**High destructive** (Impact=2, Reversibility=2 meaning partially reversible):
- Action patterns: "modify", "update", "overwrite", "chmod", "chown", "rename", "replace", "patch"
- Example: file content modification, permission changes, bulk send, config update

**Medium destructive** (Impact=1, Reversibility=1 meaning mostly reversible):
- Action patterns: "create", "send", "post", "publish", "write", "insert", "upload"
- Example: file creation, single message send, setting changes, new record

**Low/None** (Impact=0, Reversibility=0 meaning fully reversible):
- Action patterns: "read", "list", "search", "get", "health", "status", "ping", "head", "describe", "show", "count", "exists"
- Example: read-only operations, health checks, directory listings

Classification priority:
1. Tool registry metadata override: if ToolDefinition specifies RiskLevel, use it as base, then adjust for action
2. Action pattern matching: match action string against patterns
3. Parameter analysis: for ambiguous tools, check parameters:
   - "command" param containing "rm", "delete" patterns -> critical destructive
   - "force" or "recursive" flags -> increase Impact by 1
4. Unknown tools: use UnknownToolDefaults (Impact=2, Reversibility=2)

## Key Files

- POC/internal/gateway/middleware/session_context.go (modify -- add ClassifyActionDestructiveness)
  OR POC/internal/gateway/middleware/destructiveness.go (create if cleaner separation needed)

## Testing

- Unit tests: classification of known action patterns ("delete" -> Impact=3, Reversibility=3; "read" -> Impact=0, Reversibility=0; "send" -> Impact=1, Reversibility=1), parameter-based classification ("command":"rm -rf /" -> critical), tool registry override (registered tool with RiskLevel="low" keeps low Impact regardless of action), unknown tool defaults
- Integration test: sequence of destructive tool calls with classified Impact/Reversibility values triggering escalation accumulator

## Acceptance Criteria

1. ClassifyActionDestructiveness(tool, action, params) returns (impact, reversibility float64)
2. Four-tier taxonomy: critical destructive (3,3), high destructive (2,2), medium destructive (1,1), low/none (0,0)
3. Action pattern matching: "delete"/"rm"/"wipe" -> critical, "modify"/"update" -> high, "create"/"send" -> medium, "read"/"list" -> low
4. Parameter analysis: "force", "recursive" flags increase Impact
5. Tool registry metadata override: ToolDefinition.RiskLevel used as base when available
6. Unknown tools use UnknownToolDefaults (Impact=2, Reversibility=2)
7. Unit tests cover all four tiers plus parameter analysis and registry override
8. Integration test demonstrates classification feeding into escalation accumulator

## Scope Boundary

This story defines the classification function. Integration with escalation scoring (story OC-d77k calls this function) and irreversibility gating (Epic OC-xbmj reuses this taxonomy) are downstream.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T03:52:44Z dep_removed: no_longer_blocks OC-ytph

## Links
- Parent: [[OC-kd8y]]
- Led to: [[OC-d77k]], [[OC-ytph]]

## Comments
