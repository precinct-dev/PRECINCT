---
id: oc-b8i
title: "Fix stale backup-restore drill date in operations-readiness-validate"
status: closed
priority: 2
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:14Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:7a0682175f3fb1e29e08562c1e79b195fd94999e44c75a9d03abeaf145847a04"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
operations-readiness-validate fails with: 'backup/restore drill is stale: expected 2026-02-22, got 2026-02-16'. The drill artifact date is outdated. Either the drill needs to be re-run or the staleness window needs adjustment.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links


## Comments
