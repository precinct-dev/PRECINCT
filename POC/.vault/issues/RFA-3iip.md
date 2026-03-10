---
id: RFA-3iip
title: "scripts/compose-verify.sh crashes under set -u when append_unique reads an empty dockerfiles array"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T10:07:52Z
created_by: ramirosalas
updated_at: 2026-03-10T13:47:59Z
content_hash: "sha256:cd2ab5fa94adebbb4de492cd33fcfd4f162fc7ed336fb255536a37c6b31019a5"
follows: [RFA-x3ny]
labels: [accepted]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: the release verification helper `scripts/compose-verify.sh` runs with `set -euo pipefail`, but `append_unique()` currently expands `${dockerfiles[@]}` through `eval` even when the target array is empty. Under `set -u` on the release paths, that empty-array expansion raises `unbound variable` and aborts the verifier.
- Evidence:
  - During the March 10, 2026 release sanity rerun, `make demo` reached `make up` -> `compose-verify` and emitted `scripts/compose-verify.sh: line 58: dockerfiles[@]: unbound variable` before the compose bring-up continued.
  - The failure sits in the supply-chain gate itself, so a nominally green release path can start with a broken preflight even when images and Dockerfiles are correctly pinned.
  - The crash is triggered specifically when `append_unique` reads an empty target array while collecting compose Dockerfiles.
- Impact: the Makefile-first release path is brittle. `make up`, `make demo`, and any workflow depending on `compose-verify` can fail or produce misleading startup behavior because the verifier itself is not safe under `set -u`.
- Scope: harden `scripts/compose-verify.sh` so empty arrays are handled safely under `set -u`, and prove the Makefile entry points exercise the fixed verifier successfully.

## Acceptance Criteria
1. `scripts/compose-verify.sh` no longer crashes under `set -u` when `append_unique` reads an empty array while collecting Dockerfiles.
2. The compose verifier still enforces the same supply-chain checks after the fix (no regression in digest / latest-tag coverage).
3. `make up` and `make demo` no longer hit the `dockerfiles[@]: unbound variable` crash on the release path.
4. Delivery evidence includes the failing symptom, the fixed verifier command, and the passing Makefile path.

## Testing Requirements
- Reproduce or capture the failing `dockerfiles[@]: unbound variable` symptom from the Makefile-driven release path.
- Run `bash scripts/compose-verify.sh` after the fix.
- Re-run the relevant Makefile entry points (`make up`, `make demo`, or equivalent higher-level proof) so the fixed verifier is exercised in context.

## Delivery Requirements
- Append the exact failing and passing commands plus decisive output snippets.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from the March 10, 2026 release sanity rerun after `make demo` surfaced `scripts/compose-verify.sh: line 58: dockerfiles[@]: unbound variable` in the compose supply-chain verifier.

### proof
- [ ] AC #1: `append_unique` handles empty arrays safely under `set -u`.
- [ ] AC #2: Compose supply-chain verification still enforces digest / latest-tag checks after the fix.
- [ ] AC #3: The Makefile release path no longer hits the `dockerfiles[@]` crash.
- [ ] AC #4: Delivery notes include the failing symptom and the passing verifier / Makefile proof.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- The original failure was observed on the release path during story creation: `scripts/compose-verify.sh: line 58: dockerfiles[@]: unbound variable`.
- Hardened `scripts/compose-verify.sh` so `append_unique` safely reads empty arrays under `set -u` without weakening the verifier logic.
- Re-ran the verifier directly:
  - `bash scripts/compose-verify.sh`
  - Result: PASS (`No third-party services use :latest`, `All compose Dockerfile FROM references are digest-pinned`, `compose-verify: PASS`).
- Negative-path proof still holds:
  - `bash tests/e2e/compose_verify_dockerfile_pin_check.sh`
  - Result: PASS (`compose-verify rejects unpinned Dockerfile FROM references`).
- The fixed verifier is also exercised in the Makefile demo path:
  - `/tmp/make-demo-final2.log:109` -> `compose-verify: PASS`
  - `/tmp/make-demo-final2.log` ends with `ALL CYCLES PASSED`.

## nd_contract
status: delivered

### evidence
- Original crash captured during release sanity: `scripts/compose-verify.sh: line 58: dockerfiles[@]: unbound variable`.
- `bash scripts/compose-verify.sh` -> PASS.
- `bash tests/e2e/compose_verify_dockerfile_pin_check.sh` -> PASS.
- `/tmp/make-demo-final2.log` includes `compose-verify: PASS` and final `ALL CYCLES PASSED`.

### proof
- [x] AC #1: `append_unique` now handles empty arrays safely under `set -u`.
- [x] AC #2: Compose supply-chain verification still enforces the digest / latest-tag checks after the fix.
- [x] AC #3: The Makefile release path no longer hits the `dockerfiles[@]` crash.
- [x] AC #4: Delivery notes include the failing symptom and the passing verifier / Makefile proof.

## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-3iip against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-3iip` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-3iip` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
