---
id: RFA-0udk
title: "tests/e2e/common.sh crashes under set -u when gateway_request expands an empty extra_headers array"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T10:13:20Z
created_by: ramirosalas
updated_at: 2026-03-10T13:44:53Z
content_hash: "sha256:d57ce051743de3d0542a4250285e8f81a899068ad212db92a8c34fcb6c11af3d"
follows: [RFA-x3ny]
labels: [accepted]
closed_at: 2026-03-10T13:44:53Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: the shared e2e harness `tests/e2e/common.sh` runs with `set -euo pipefail`, but `gateway_request()` expands `"${extra_headers[@]}"` even when no extra headers were supplied. Under the shell/runtime used by the Makefile release path, that empty-array expansion is treated as unbound and aborts the scenario before curl sends the request.
- Evidence:
  - During the March 10, 2026 release sanity rerun, `make demo` reached `tests/e2e/scenario_h_extensions.sh` and every request in the extension slot scenario failed with `tests/e2e/common.sh: line 138: extra_headers[@]: unbound variable`.
  - The scenario then reported blank response codes/bodies and false-negative failures for clean-request allow, prompt-injection block, and eval-pattern flag-and-allow checks.
  - The issue reproduces through the Makefile-first release path and prevents `make demo` from completing even when the product behavior behind the extension slot is healthy.
- Impact: the canonical e2e harness is brittle under `set -u`, so release validation can fail because of shell plumbing rather than a real regression.
- Scope: harden `gateway_request()` so zero or more extra headers are safe under `set -u`, and prove the extension scenario plus `make demo` pass with the fixed harness.

## Acceptance Criteria
1. `tests/e2e/common.sh` no longer crashes under `set -u` when `gateway_request()` is called without extra headers.
2. `tests/e2e/scenario_h_extensions.sh` issues its requests normally and passes when the running stack is healthy.
3. `make demo` no longer fails due to the `extra_headers[@]: unbound variable` harness crash.
4. Delivery evidence includes the failing symptom and the passing scenario / Makefile path.

## Testing Requirements
- Capture the failing `extra_headers[@]: unbound variable` symptom from the release validation path.
- Re-run `bash tests/e2e/scenario_h_extensions.sh` against a healthy stack after the fix.
- Re-run `make demo` after the fix so the repaired harness is exercised in the canonical release flow.

## Delivery Requirements
- Append the exact failing and passing commands plus decisive output snippets.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from the March 10, 2026 release sanity rerun after `make demo` surfaced `tests/e2e/common.sh: line 138: extra_headers[@]: unbound variable` in the extension slot scenario.

### proof
- [ ] AC #1: `gateway_request()` handles empty extra header lists safely under `set -u`.
- [ ] AC #2: The extension slot scenario passes with the repaired harness.
- [ ] AC #3: `make demo` no longer fails due to the `extra_headers[@]` crash.
- [ ] AC #4: Delivery notes include the failing symptom and the passing scenario / Makefile proof.

## Acceptance Criteria


## Design


## Notes

## PM Acceptance
- Reviewed delivery evidence and release validation proof.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `make demo > /tmp/make-demo-final3.log 2>&1` -> PASS (`ALL CYCLES PASSED`).
  - `make story-evidence-validate STORY_ID=RFA-0udk` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's delivery notes remain consistent with the final release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-0udk` -> PASS.

### proof
- [x] AC #1: Verified against recorded delivery evidence and final Makefile release run.
- [x] AC #2: Verified against recorded delivery evidence and final Makefile release run.
- [x] AC #3: Verified against recorded delivery evidence and final Makefile release run.
- [x] AC #4: Verified against recorded delivery evidence and final Makefile release run.

## Delivery Notes
- Captured the original harness failure from `/tmp/make-demo-final.log`:
  - `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/common.sh: line 138: extra_headers[@]: unbound variable`
- Hardened `tests/e2e/common.sh` so `gateway_request()` safely handles zero extra headers under `set -u`.
- Re-ran the extension-slot scenario directly:
  - `bash tests/e2e/scenario_h_extensions.sh`
  - Result: PASS (`All checks passed.`) with clean request allow, prompt-injection block, and eval-pattern allow/flag checks all green.
- End-to-end demo proof already exercised the same repaired harness:
  - `/tmp/make-demo-final2.log` includes `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, and final `ALL CYCLES PASSED`.

## nd_contract
status: delivered

### evidence
- Failing symptom preserved from `/tmp/make-demo-final.log`: `tests/e2e/common.sh: line 138: extra_headers[@]: unbound variable`.
- `bash tests/e2e/scenario_h_extensions.sh` -> PASS (`All checks passed.`).
- `/tmp/make-demo-final2.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.

### proof
- [x] AC #1: `gateway_request()` now handles empty extra header lists safely under `set -u`.
- [x] AC #2: `tests/e2e/scenario_h_extensions.sh` passes against the healthy stack.
- [x] AC #3: `make demo` no longer fails due to the `extra_headers[@]` crash.
- [x] AC #4: Delivery notes include the failing symptom and the passing scenario / Makefile proof.

## History
- 2026-03-10T13:44:53Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-0udk against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-0udk` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-0udk` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
