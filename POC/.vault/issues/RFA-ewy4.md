---
id: RFA-ewy4
title: "Strict overlay operationalization validator rejects digest-pinned GHCR images"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T10:54:12Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:0375fdb4e0dd5e537c9eadeda80d62527dff46eca194bde420671efff7fff326"
follows: [RFA-x3ny]
labels: [accepted]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: `make k8s-validate` fails in `tests/e2e/validate_strict_overlay_operationalization.sh` even when staging/prod overlays render the correct promoted GHCR images.
- Evidence:
  - On March 10, 2026, `make k8s-validate` failed with `[FAIL] staging: gateway image is not set to a non-placeholder GHCR path`.
  - The rendered staging/prod overlays already use promoted digest-pinned images such as `ghcr.io/ramxx/agentic-ref-arch/mcp-security-gateway@sha256:...` and `ghcr.io/ramxx/agentic-ref-arch/s3-mcp-server@sha256:...`.
  - The validator still greps only for tag-shaped image references ending in `:`, so it rejects the stricter digest form that the promotion pipeline intentionally emits.
- Impact: the Makefile-backed K8s release validation produces false negatives and obscures real overlay regressions.
- Scope: update the strict overlay operationalization validator to accept non-placeholder GHCR images whether they are tag-pinned or digest-pinned, then rerun `make k8s-validate`.

## Acceptance Criteria
1. `tests/e2e/validate_strict_overlay_operationalization.sh` accepts digest-pinned GHCR images for the gateway and MCP server checks.
2. The validator still rejects placeholder owners and placeholder runtime images.
3. `make k8s-validate` passes after the validator fix.
4. Delivery evidence includes the failing validator output and the passing rerun.

## Testing Requirements
- Capture the failing `make k8s-validate` output.
- Re-run `make k8s-validate` after the validator fix.

## Delivery Requirements
- Append the exact failing and passing commands plus decisive output snippets.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from the March 10, 2026 release sanity rerun after `make k8s-validate` rejected digest-pinned GHCR images in staging/prod overlays.

### proof
- [ ] AC #1: The strict overlay validator accepts digest-pinned GHCR gateway and MCP server images.
- [ ] AC #2: Placeholder-image rejection still remains intact.
- [ ] AC #3: `make k8s-validate` passes after the validator fix.
- [ ] AC #4: Delivery notes include the failing and passing Makefile evidence.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- Captured the original validator false-negative from `/tmp/make-k8s-validate.log`:
  - `[FAIL] staging: gateway image is not set to a non-placeholder GHCR path`
- Updated `tests/e2e/validate_strict_overlay_operationalization.sh` to accept digest-pinned GHCR images, which is the stricter release contract now rendered by staging/prod overlays.
- Re-ran the full Makefile-backed validation:
  - `make k8s-validate`
  - Result: PASS (`/tmp/make-k8s-validate-final.log` ends with `k8s-validate: PASS` and confirms `Strict overlay operationalization validation passed`).

## nd_contract
status: delivered

### evidence
- `/tmp/make-k8s-validate.log` captured the original false-negative: `[FAIL] staging: gateway image is not set to a non-placeholder GHCR path`.
- `/tmp/make-k8s-validate-final.log` confirms the repaired validator accepts the rendered digest-pinned GHCR images and ends with `k8s-validate: PASS`.

### proof
- [x] AC #1: The strict overlay validator now accepts digest-pinned GHCR gateway and MCP server images.
- [x] AC #2: Placeholder-image rejection remains intact as part of the same validation surface.
- [x] AC #3: `make k8s-validate` passes after the validator fix.
- [x] AC #4: Delivery notes include the failing and passing Makefile evidence.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-ewy4 against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-ewy4` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-ewy4` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
