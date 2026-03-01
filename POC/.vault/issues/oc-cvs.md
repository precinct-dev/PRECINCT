---
id: oc-cvs
title: "Fix regex bug in scripts/upgrade.sh causing upgrade-all failure"
status: closed
priority: 1
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:04Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:b1c646c7f5623429d6fe3800edd5470cbf3d8f502c058901d062a95272a19bce"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
scripts/upgrade.sh has an unmatched parenthesis in a Perl regex, causing 'make upgrade-all' to fail with: Unmatched ( in regex. The regex patterns matching otel and phoenix images need escaping. This script has never been modified since its initial commit (8142384).

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links


## Comments
