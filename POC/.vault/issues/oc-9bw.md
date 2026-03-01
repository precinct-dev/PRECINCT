---
id: oc-9bw
title: "Fix stale compose log in gateway-bypass-case26-validate"
status: closed
priority: 2
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:22Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:beb808b686061394b3d42fe5ea4d5aebb9745b2d250efc7cd6e7e20382ee45ce"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
gateway-bypass-case26-validate fails with: 'No Go case26 PASS proof found in compose log'. The test references a stale log artifact from 2026-02-16. The validation needs fresh logs from a current demo-compose run, or the artifact needs regeneration.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links


## Comments
