---
id: oc-cvs
title: "Fix regex bug in scripts/upgrade.sh causing upgrade-all failure"
status: closed
priority: 1
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-22T00:42:04Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:fb3792fba1a9009dc016ef20d9b8a604aa6ed080e670bb6a448d2f60c0ee11dc"
closed_at: 2026-02-22T01:08:06Z
close_reason: "All 7 bugs fixed and verified: lint 0 issues, test 67/67, readiness-state-validate PASS, operations-readiness-validate PASS, gateway-bypass-case26-validate PASS"
---

## Description
scripts/upgrade.sh has an unmatched parenthesis in a Perl regex, causing 'make upgrade-all' to fail with: Unmatched ( in regex. The regex patterns matching otel and phoenix images need escaping. This script has never been modified since its initial commit (8142384).

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
