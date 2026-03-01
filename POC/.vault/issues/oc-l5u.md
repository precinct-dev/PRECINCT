---
id: oc-l5u
title: "Post-Gap-Closure Technical Debt"
status: closed
priority: 1
type: epic
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T17:52:57Z
created_by: ramirosalas
updated_at: 2026-02-27T03:51:55Z
content_hash: "sha256:945264bd7d6c5627dcff99bb1332dd1a542a628829b52e8dedffaa95574b12ca"
closed_at: 2026-02-21T18:01:36Z
close_reason: "All 3 tech debt items resolved: race conditions fixed (getMCPTransport + LastHash accessors), ARN placeholders corrected, go.mod verified clean."
led_to: [oc-6bq]
---

## Description
Epic for technical debt items discovered during engineering gap closure work (GAP-1 through GAP-7). These are pre-existing defects and hygiene issues that were documented but out-of-scope during gap remediation. All items are P1: two are real defects that would cause test failures or IAM validation errors, and one is a dependency hygiene issue that should be verified and corrected.

Context: All 7 engineering gap stories are closed across both epics. The test suite passes fully (1294 tests) except for two known race conditions documented here. The beads tracker was at zero open issues before this epic.

Scope:
1. Fix data races in MCP transport tests (go test -race failures)
2. Fix malformed ARN placeholders in infra/eks/ YAML manifests
3. Verify and correct gorilla/websocket and gojsonschema dependency classification in go.mod

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links
- Led to: [[oc-6bq]]

## Comments
