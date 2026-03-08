---
id: oc-9bw
title: "Fix stale compose log in gateway-bypass-case26-validate"
status: closed
priority: 2
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:22Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:6a99df7c8212037449042d632a569bd8252900ab578b1295174fb46f61395fb5"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
gateway-bypass-case26-validate fails with: 'No Go case26 PASS proof found in compose log'. The test references a stale log artifact from 2026-02-16. The validation needs fresh logs from a current demo-compose run, or the artifact needs regeneration.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
