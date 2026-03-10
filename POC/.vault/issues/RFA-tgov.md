---
id: RFA-tgov
title: "Compose demo rerun cycle leaks stale session state through fixed demo session IDs"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T08:44:47Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:b4dcdc7d8071ec99311173ca1d48071cbff8cb54830916758fcd7e59d81fbd44"
labels: [release-sanity, robustness, workflow, demo, accepted]
follows: [RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Description
## Context (Embedded)
- Problem: `demo/run.sh compose` intentionally reruns the demo campaign for repeatability, but the Go and Python demo clients reused fixed session IDs for stateful scenarios such as principal hierarchy, reversibility, DLP escalation, and session-based step-up checks.
- Evidence:
  - After the first compose cycle succeeded, the second cycle reused the same hard-coded session identifiers and inherited prior session state from the gateway and KeyDB.
  - This caused spurious failures that did not reflect a fresh-user workflow; the demo was proving persistence leakage between reruns rather than the intended control behavior for a new session.
  - Updating the demos to generate per-run unique session IDs for the stateful scenarios restored deterministic rerun behavior and allowed the compose demo campaign to pass across repeated cycles.
- Impact: The release demo path is not reliable under repeat execution, which undermines confidence in `make demo-compose`, `make demo`, and any operator workflow that expects a clean rerun without manual state surgery. Because the failure is rooted in stale session identity reuse, it can also mask or misattribute genuine security-control outcomes.
- Scope: This story is about making demo validation idempotent across reruns by ensuring stateful scenarios use fresh session identifiers per execution while preserving the security assertions each scenario is intended to prove.

## Acceptance Criteria
1. Stateful Go and Python demo scenarios no longer use fixed session IDs that can collide across compose rerun cycles.
2. The demo coverage still proves the same principal, reversibility, DLP, and escalation outcomes after switching to per-run unique session IDs.
3. `make demo-compose` completes successfully across the built-in rerun cycle without inheriting stale session state from cycle 1.
4. Delivery evidence clearly ties the prior rerun failure mode to hard-coded session reuse and includes the passing rerun result after the fix.

## Testing Requirements
- Code-level: update both demo clients where stateful scenarios currently use fixed session identifiers.
- Runtime: rerun `make demo-compose` end to end so the built-in second cycle exercises the fix.
- Regression: if targeted checks exist for the renamed or adjusted demo expectations, run them alongside the full demo.
- Commands to run:
  - `python3 -m py_compile demo/python/demo.py`
  - relevant Go test or compile command if the Go demo helpers change
  - `make demo-compose`

## Delivery Requirements
- Append the exact rerun command and the decisive output proving both cycles passed.
- Reference the specific demo files and scenario families updated to use unique session IDs.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from release-validation retest after the compose demo passed once but rerun-cycle stateful scenarios failed because fixed session IDs leaked prior gateway/session state into cycle 2.

### proof
- [ ] AC #1: Stateful demo scenarios use per-run unique session IDs instead of fixed IDs.
- [ ] AC #2: The same demo security assertions still hold with the new session-ID strategy.
- [ ] AC #3: `make demo-compose` passes across the built-in rerun cycle.
- [ ] AC #4: Delivery notes include the pre-fix rerun failure mode and the passing rerun evidence.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- Removed fixed session-ID reuse from the stateful compose demo scenarios so rerun cycle 2 no longer inherits stale gateway / KeyDB state from cycle 1.
- Python demo syntax sanity was rechecked:
  - `python3 -m py_compile demo/python/demo.py`
  - Result: PASS.
- End-to-end rerun proof from the release pass:
  - `/tmp/make-demo-final2.log` includes two green compose cycles (`ALL DEMOS PASSED (compose)` at lines 2088 and 3426) and overall compose `ALL CYCLES PASSED` at line 3432.
  - The combined demo run also finishes with final `ALL CYCLES PASSED`.

## nd_contract
status: delivered

### evidence
- Stateful demo scenarios now generate per-run unique session IDs instead of reusing fixed IDs across rerun cycles.
- `Makefile` remains the canonical validation surface for the rerun-hardening proof via `make demo-compose`.
- `python3 -m py_compile demo/python/demo.py` -> PASS.
- `/tmp/make-demo-final2.log` shows both compose cycles green and compose `ALL CYCLES PASSED`.

### proof
- [x] AC #1: Stateful Go and Python demo scenarios no longer collide on fixed session IDs across reruns.
- [x] AC #2: The same principal, reversibility, DLP, and escalation assertions still hold with per-run unique IDs.
- [x] AC #3: `make demo-compose` passes across the built-in rerun cycle without stale session leakage.
- [x] AC #4: Delivery notes tie the prior rerun failure mode to hard-coded session reuse and include the passing rerun proof.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## Acceptance Criteria


## Design


## Notes


## History


## Links


## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-tgov against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-tgov` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-tgov` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
