---
id: OC-lmzm
title: "Pre-Action State Snapshot Recommendation"
status: closed
priority: 2
type: task
labels: [agents-of-chaos, irreversibility]
parent: OC-xbmj
created_at: 2026-03-08T02:44:34Z
created_by: ramirosalas
updated_at: 2026-03-08T17:35:05Z
content_hash: "sha256:42a98dda01bc7b97aa88d26dd099b0179e1b567197183f1077b1615897e88d83"
was_blocked_by: [OC-h4m7, OC-ytph]
closed_at: 2026-03-08T17:35:05Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## User Story

As a security operator, I need the gateway to recommend pre-action state snapshots for irreversible or partially reversible actions so that agent frameworks have a structured signal to preserve state before destructive operations.

## Context

Story OC-ytph defines ActionReversibility with RequiresBackup bool (true for Score >= 2). This story adds a response header that signals to the agent framework that a backup should be taken before the authorized action executes.

This is advisory -- the gateway cannot force an agent to take a backup. It provides the signal; the agent framework decides whether to act on it.

Existing header contract: X-Precinct-Principal-Level, X-Precinct-Principal-Role (from story OC-t7go), X-Precinct-Reversibility (from story OC-h4m7).

## Implementation

When ActionReversibility.RequiresBackup == true AND the action is allowed (not blocked by step-up gating):

1. Add X-Precinct-Backup-Recommended: true header to the proxied request
2. Audit log records that backup was recommended
3. Session context records that a destructive action was authorized (contributes to escalation tracking from story OC-12ng)

When RequiresBackup == false or action is denied:
- Header is not set (or set to "false")

Document the header contract:
- Header name: X-Precinct-Backup-Recommended
- Values: "true" or absent
- When set: the action has been classified as partially reversible or irreversible (Score >= 2)
- Meaning: the agent framework should consider taking a state snapshot before executing the action
- Not set: the action is fully or mostly reversible, no backup needed

## Key Files

- POC/internal/gateway/middleware/step_up_gating.go (modify -- add backup header injection)
- POC/internal/gateway/middleware/audit.go (modify -- record backup recommendation)
- POC/docs/api-reference.md (modify -- document new header)

## Testing

- Unit tests: backup recommendation header set when RequiresBackup=true and action allowed, header absent when RequiresBackup=false, header absent when action denied (no need for backup if action blocked)
- Integration test: irreversible action allowed for owner -> response includes X-Precinct-Backup-Recommended: true

## Acceptance Criteria

1. X-Precinct-Backup-Recommended: true header set on proxied request when RequiresBackup=true and action allowed
2. Header absent when RequiresBackup=false or action denied
3. Audit log records backup recommendation event
4. Session context records authorized destructive action for escalation tracking
5. Header contract documented in api-reference.md
6. Unit tests verify header presence/absence in all scenarios
7. Integration test demonstrates header on allowed irreversible action

## Dependencies

Depends on OC-ytph (ActionReversibility with RequiresBackup), OC-h4m7 (step-up gating integration where allowed/denied decision is made).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z dep_removed: was_blocked_by OC-ytph

## Links
- Parent: [[OC-xbmj]]
- Was blocked by: [[OC-h4m7]], [[OC-ytph]]

## Comments
