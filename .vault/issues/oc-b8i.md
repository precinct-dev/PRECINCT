---
id: oc-b8i
title: "Fix stale backup-restore drill date in operations-readiness-validate"
status: closed
priority: 2
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:14Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:9331d93035b20160b70d43d539f11d8504873e81267d6a6be3306cc6980a325c"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
operations-readiness-validate fails with: 'backup/restore drill is stale: expected 2026-02-22, got 2026-02-16'. The drill artifact date is outdated. Either the drill needs to be re-run or the staleness window needs adjustment.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
