---
id: RFA-565d
title: "Release workflow and validation still depend on bd/beads instead of nd"
status: closed
priority: 0
type: bug
labels: [release-sanity, robustness, workflow, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T06:41:31Z
created_by: ramirosalas
updated_at: 2026-03-10T13:47:59Z
content_hash: "sha256:c44dd31c1f18eda4904113571c23204a506a8706f6c394a6bd94e7b0d7beac01"
follows: [RFA-x3ny, RFA-aszr, RFA-odey, RFA-k7l5]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Description
## Context (Embedded)
- Problem: The repo still exposes release and validation workflows that depend on historical `bd`/beads even though `nd` is now the canonical tracker.
- Evidence:
  - `AGENTS.md` instructs agents to use `bd onboard`, `bd ready`, `bd update`, `bd close`, and `bd sync`.
  - `Makefile` target `story-evidence-validate` still says it validates evidence paths in a `bd` story.
  - `tests/e2e/validate_story_evidence_paths.sh` and `tests/e2e/validate_readiness_state_integrity.sh` hard-require `bd`.
  - `README.md`, release docs, and multiple runbooks still refer to beads/`bd` as the active planning or evidence system.
  - User clarification on 2026-03-10: beads is historical; `nd` is the real tracker now.
- Impact: Release operators, external reviewers, and future agents can follow stale commands, fail validation flows, or distrust the repo’s process maturity because the documented tracker contract contradicts the real one.

## Acceptance Criteria
1. Release-facing workflow instructions use `nd` as the canonical tracker in repo entrypoints such as `AGENTS.md` and `README.md`.
2. Makefile-backed validation flows and supporting scripts no longer require `bd` when `nd` is the intended tracker, including story-evidence/readiness validation paths that are still part of the release workflow.
3. Release/runbook/current-state documentation is internally consistent about `nd` vs historical beads references, with any historical references clearly marked as archival context rather than active process.

## Testing Requirements
- Run targeted validation proving the updated scripts/targets work with `nd` instead of `bd`.
- Add or update at least one Makefile-oriented verification path for the tracker-backed evidence flow if needed.
- Run a repo search over the touched release-process surfaces and capture the remaining `bd`/beads references, confirming any survivors are intentionally historical.

## nd_contract
status: new

### evidence
- Created from 2026-03-10 release sanity follow-up after user clarified that beads is historical and `nd` is canonical.
- Embedded evidence references `AGENTS.md`, `Makefile`, `tests/e2e/validate_story_evidence_paths.sh`, `tests/e2e/validate_readiness_state_integrity.sh`, `README.md`, and release/runbook docs.

### proof
- [ ] AC #1: Entry-point workflow docs point to `nd` as the active tracker.
- [ ] AC #2: Makefile/scripts used for release validation work without `bd` assumptions.
- [ ] AC #3: Release-facing docs consistently treat beads references as historical only.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Kept the active tracker audit inside `POC/Makefile` so the story stays within the requested tracker-migration/workflow surface; no standalone tracker validator script remains in `tests/e2e/`.
- Updated `POC/tests/e2e/validate_story_evidence_paths.sh` to read the current delivery block from the `## Notes` section, matching `nd update --append-notes` prepend semantics for append-only story histories.
- Validation commands passed with exact outputs:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
    - `[PASS] oc-ko5 status matches (closed)`
    - `[PASS] readiness state integrity validation passed`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`
    - `[PASS] release workflow surfaces use nd as the active tracker; remaining beads references are archival only`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d`
    - `[PASS] Makefile`
    - `[PASS] AGENTS.md`
    - `[PASS] README.md`
    - `[PASS] docs/current-state-and-roadmap.md`
    - `[PASS] docs/deployment-guide.md`
    - `[PASS] docs/operations/runbooks/incident-triage-and-response.md`
    - `[PASS] docs/operations/runbooks/rollback-runbook.md`
    - `[PASS] docs/operations/runbooks/security-event-response.md`
    - `[PASS] docs/security/evidence-collection.md`
    - `[PASS] tests/e2e/validate_readiness_state_integrity.sh`
    - `[PASS] tests/e2e/validate_story_evidence_paths.sh`
    - `[PASS] evidence paths validated for RFA-565d`
- Repo search over touched workflow surfaces shows only archival/historical beads references in docs plus the validator implementation lines in `POC/Makefile`.
- Self-check for stub/TODO markers over the touched files returned no matches.

### proof
- [x] AC #1: `POC/AGENTS.md` and `POC/README.md` now present `nd` as the canonical tracker for active release workflow.
- [x] AC #2: `POC/Makefile`, `POC/tests/e2e/validate_story_evidence_paths.sh`, and `POC/tests/e2e/validate_readiness_state_integrity.sh` now validate active workflow state against `nd`, and the Make-backed tracker audit runs without `bd` assumptions.
- [x] AC #3: `POC/docs/current-state-and-roadmap.md`, `POC/docs/deployment-guide.md`, `POC/docs/security/evidence-collection.md`, and the touched runbooks now treat beads references as archival context only.

## Implementation Evidence (DELIVERED)

### Changed Files
- POC/AGENTS.md
- POC/README.md
- POC/Makefile
- POC/docs/current-state-and-roadmap.md
- POC/docs/deployment-guide.md
- POC/docs/operations/runbooks/incident-triage-and-response.md
- POC/docs/operations/runbooks/rollback-runbook.md
- POC/docs/operations/runbooks/security-event-response.md
- POC/docs/security/evidence-collection.md
- POC/tests/e2e/validate_story_evidence_paths.sh
- POC/tests/e2e/validate_readiness_state_integrity.sh

### CI/Test Results
- Commands run:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`
  - `rg -n "\bbd\b|beads" /Users/ramirosalas/workspace/agentic_reference_architecture/POC/AGENTS.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/Makefile /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_story_evidence_paths.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_readiness_state_integrity.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/current-state-and-roadmap.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/deployment-guide.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/security/evidence-collection.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/incident-triage-and-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/rollback-runbook.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/security-event-response.md`
  - `rg -n "TODO|NotImplementedError|panic\(\"todo\"\)|unimplemented!" /Users/ramirosalas/workspace/agentic_reference_architecture/POC/AGENTS.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/Makefile /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_story_evidence_paths.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_readiness_state_integrity.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/current-state-and-roadmap.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/deployment-guide.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/security/evidence-collection.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/incident-triage-and-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/rollback-runbook.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/security-event-response.md`
- Summary:
  - `readiness-state-validate`: PASS (`[PASS] oc-ko5 status matches (closed)`; `[PASS] readiness state integrity validation passed`).
  - `tracker-surface-validate`: PASS (`[PASS] release workflow surfaces use nd as the active tracker; remaining beads references are archival only`).
  - Tracker surface search shows only archival/historical documentation references plus the `Makefile` validator implementation lines.
  - Stub/self-check search returned no matches in the touched files.

### Repo Search Follow-Up
- Intentional archival references remain in:
  - `POC/AGENTS.md`
  - `POC/README.md`
  - `POC/docs/current-state-and-roadmap.md`
  - `POC/docs/deployment-guide.md`
- Validator implementation references remain in:
  - `POC/Makefile`

### Working Tree Notes
- Worktree remains shared and dirty with unrelated in-flight changes outside this story scope.
- Delivery for `RFA-565d` stayed within the allowed tracker-migration/workflow surface and did not modify gateway, SDK, or EKS/compose runtime files.

### AC Verification
| AC # | Requirement | Status |
|------|-------------|--------|
| 1 | Release-facing workflow instructions use `nd` as the canonical tracker in entry-point docs. | PASS |
| 2 | Makefile-backed validation flows and supporting scripts no longer require `bd` for the active tracker workflow. | PASS |
| 3 | Release/runbook/current-state documentation treats beads references as historical or archival context only. | PASS |

## nd_contract
status: delivered

### evidence
- Updated active tracker entrypoints and release-process surfaces to use `nd`: `AGENTS.md`, `README.md`, `Makefile`, `tests/e2e/validate_story_evidence_paths.sh`, `tests/e2e/validate_readiness_state_integrity.sh`, `docs/current-state-and-roadmap.md`, `docs/operations/runbooks/incident-triage-and-response.md`, `docs/operations/runbooks/security-event-response.md`, `docs/operations/runbooks/rollback-runbook.md`, `docs/security/evidence-collection.md`, and `docs/deployment-guide.md`.
- Removed remaining active beads cleanup logic from `Makefile`; surviving beads references are explicitly historical (`README.md` archival hook note, `docs/current-state-and-roadmap.md` archival metrics note).
- `make story-evidence-validate STORY_ID=RFA-4oss` -> PASS (`[PASS] docs/api-reference.md`, `[PASS] internal/gateway/phase3_plane_stubs.go`, `[PASS] internal/gateway/phase3_tool_cli_test.go`).
- `make readiness-state-validate` -> PASS (`[PASS] oc-ko5 status matches (closed)`, `[PASS] readiness state integrity validation passed`).
- `rg -n '\bbd\b|beads' ...` across the touched workflow/docs surfaces now returns only intentional historical references in `README.md` and `docs/current-state-and-roadmap.md`.

### proof
- [x] AC #1: Entry-point workflow docs now point to `nd` as the active tracker (`AGENTS.md`, `README.md`).
- [x] AC #2: Make-backed evidence/readiness validation runs against `nd` JSON output instead of `bd`, proven by the passing `make story-evidence-validate` and `make readiness-state-validate` commands.
- [x] AC #3: Release-facing docs now describe beads references as archival only; no touched workflow surface still instructs operators to use `bd` for active work.

## nd_contract
status: delivered

### evidence
- Final authoritative delivery block appended after prior historical notes so the last nd_contract is definitive.
- Validation commands passed:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`
- Remaining `bd`/beads hits in touched surfaces are archival-only notes plus the validator implementation.

### proof
- [x] AC #1: Entry-point workflow docs now use `nd` as the active tracker.
- [x] AC #2: Makefile-backed evidence/readiness validation now runs on `nd` story data and includes a tracker-surface audit.
- [x] AC #3: Release-facing docs now mark any surviving beads references as historical or archival context only.

## Implementation Evidence (DELIVERED)

### Changed Files
- POC/AGENTS.md
- POC/README.md
- POC/Makefile
- POC/docs/current-state-and-roadmap.md
- POC/docs/deployment-guide.md
- POC/docs/operations/runbooks/incident-triage-and-response.md
- POC/docs/operations/runbooks/rollback-runbook.md
- POC/docs/operations/runbooks/security-event-response.md
- POC/docs/security/evidence-collection.md
- POC/tests/e2e/validate_story_evidence_paths.sh
- POC/tests/e2e/validate_readiness_state_integrity.sh
- POC/tests/e2e/validate_tracker_surface_consistency.sh

### CI/Test Results
- Commands run:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`
  - `rg -n "\bbd\b|beads" /Users/ramirosalas/workspace/agentic_reference_architecture/POC/AGENTS.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/Makefile /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/current-state-and-roadmap.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/deployment-guide.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/security/evidence-collection.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/incident-triage-and-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/rollback-runbook.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/security-event-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_story_evidence_paths.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_readiness_state_integrity.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_tracker_surface_consistency.sh`
  - `rg -n "TODO|NotImplementedError|panic\("todo"\)|unimplemented!" /Users/ramirosalas/workspace/agentic_reference_architecture/POC/AGENTS.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/README.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/Makefile /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/current-state-and-roadmap.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/deployment-guide.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/incident-triage-and-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/rollback-runbook.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/operations/runbooks/security-event-response.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/docs/security/evidence-collection.md /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_story_evidence_paths.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_readiness_state_integrity.sh /Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/e2e/validate_tracker_surface_consistency.sh`
- Summary:
  - `story-evidence-validate`: PASS for `AGENTS.md`, `Makefile`, `README.md`, `docs/current-state-and-roadmap.md`, `tests/e2e/validate_readiness_state_integrity.sh`, and `tests/e2e/validate_story_evidence_paths.sh` referenced in `RFA-565d`.
  - `readiness-state-validate`: PASS against `docs/status/production-readiness-state.json`; confirmed `oc-ko5` closed and no external-app gate snapshot present.
  - `tracker-surface-validate`: PASS; active release workflow surfaces now use `nd`, and remaining `bd`/beads matches are archival-only notes plus the validator implementation itself.
  - Stub/self-check search: PASS with no TODO/unimplemented markers in touched files.

### Repo Search Follow-Up
- Remaining `bd`/beads references in touched surfaces are intentional archival context only:
  - `POC/AGENTS.md` archival notice
  - `POC/README.md` historical hook compatibility section
  - `POC/docs/current-state-and-roadmap.md` archival beads-era closure-chain notes
  - `POC/docs/deployment-guide.md` archival note for historical `RFA-*` campaign IDs
  - `POC/tests/e2e/validate_tracker_surface_consistency.sh` (validator patterns/messages)

### Working Tree Notes
- Delivery was made on shared branch `story/RFA-4oss` with unrelated in-flight changes already present in the worktree.
- No commit was created because the branch is shared/dirty and the request was to deliver proof back into `nd` without disturbing unrelated agent work.

### AC Verification
| AC # | Requirement | Status |
|------|-------------|--------|
| 1 | Release-facing workflow instructions use `nd` as canonical tracker in entry-point docs. | PASS |
| 2 | Makefile-backed validation flows and supporting scripts no longer require `bd`. | PASS |
| 3 | Release/runbook/current-state docs treat beads references as archival only. | PASS |

## nd_contract
status: delivered

### evidence
- Updated tracker/workflow entrypoints: `POC/AGENTS.md`, `POC/README.md`, `POC/Makefile`.
- Updated release-facing docs/runbooks: `POC/docs/current-state-and-roadmap.md`, `POC/docs/deployment-guide.md`, `POC/docs/operations/runbooks/incident-triage-and-response.md`, `POC/docs/operations/runbooks/rollback-runbook.md`, `POC/docs/operations/runbooks/security-event-response.md`, `POC/docs/security/evidence-collection.md`.
- Updated `nd`-backed validators: `POC/tests/e2e/validate_story_evidence_paths.sh`, `POC/tests/e2e/validate_readiness_state_integrity.sh`, `POC/tests/e2e/validate_tracker_surface_consistency.sh`.
- Validation commands passed:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`

### proof
- [x] AC #1: Entry-point workflow docs now instruct operators/agents to use `nd`, with beads noted as archival compatibility only.
- [x] AC #2: `story-evidence-validate` and `readiness-state-validate` execute against live `nd`, and `tracker-surface-validate` adds a Make-backed audit for stale tracker references.
- [x] AC #3: Release-facing docs/runbooks/current-state content now describe any remaining beads references as archival context rather than active process.

## nd_contract
status: delivered

### evidence
- Updated active workflow surfaces to treat `nd` as canonical in `AGENTS.md`, `README.md`, `Makefile`, `tests/e2e/validate_story_evidence_paths.sh`, `tests/e2e/validate_readiness_state_integrity.sh`, and release/runbook docs.
- `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d` -> PASS.
- `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate` -> PASS.
- `rg -n "\bbd\b|beads" ...` across the touched release-process surfaces now shows only clearly historical compatibility references in `README.md` and an archival metrics note in `docs/current-state-and-roadmap.md`.

### proof
- [x] AC #1: Entry-point workflow docs now point to `nd` as the active tracker in `AGENTS.md` and `README.md`.
- [x] AC #2: Makefile-backed evidence/readiness validation now runs on `nd` story data instead of `bd`.
- [x] AC #3: The touched release-facing docs now treat remaining beads mentions as historical context only.

## nd_contract
status: in_progress

### evidence
- Claimed: 2026-03-10 by Codex developer workflow in /Users/ramirosalas/workspace/agentic_reference_architecture/POC.
- Scope confirmed from story: tracker/workflow surfaces only (AGENTS.md, README.md, Makefile, release-validation scripts/docs still requiring bd/beads).
- Worktree note: branch is currently story/RFA-4oss with unrelated in-flight changes from other agents; this story will avoid reverting or editing unrelated runtime/security files.

### proof
- [ ] AC #1: Entry-point workflow docs point to nd as the active tracker.
- [ ] AC #2: Makefile/scripts used for release validation work without bd assumptions.
- [ ] AC #3: Release-facing docs consistently treat beads references as historical only.

## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]], [[RFA-aszr]], [[RFA-odey]], [[RFA-k7l5]]

## Comments

## Acceptance Criteria


## Design


## Notes


## History


## Links


## Comments

## nd_contract
status: delivered

### evidence
- Final authoritative delivery block appended at end-of-file so the last nd_contract is definitive for PM acceptance.
- Validation commands passed:
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC story-evidence-validate STORY_ID=RFA-565d`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC readiness-state-validate`
  - `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC tracker-surface-validate`
- Remaining `bd`/beads hits in touched surfaces are archival-only notes plus the validator implementation.

### proof
- [x] AC #1: Entry-point workflow docs now use `nd` as the active tracker.
- [x] AC #2: Makefile-backed evidence/readiness validation now runs on `nd` story data and includes a tracker-surface audit.
- [x] AC #3: Release-facing docs now mark any surviving beads references as historical or archival context only.

## PM Acceptance
- Reviewed the delivered proof for RFA-565d against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-565d` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-565d` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
