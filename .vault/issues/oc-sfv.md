---
id: oc-sfv
title: "Fix KeyDB port not host-mapped, breaking agw-demo/agw-operate-demo/compliance-demo"
status: closed
priority: 1
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:08Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:384008b207455dfdcc7ab05fa9420ad4555c44e23a95292d0425e0d0052f1128"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
The agw E2E tests (test_agw_cli.sh, test_agw_operate.sh, test_agw_compliance.sh) expect KeyDB at redis://localhost:6379, but docker-compose.yml does not map KeyDB's port to the host. This causes agw-demo, agw-operate-demo, and compliance-demo to fail at the keydb health check. Either the compose file needs a port mapping or the tests need to use the Docker network.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
