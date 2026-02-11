# Retrospective: RFA-cxbk - Container Repave for APT Mitigation

## Source Stories
- RFA-4ldp (accepted)
- RFA-67xd (accepted)
- RFA-cfyd (accepted)
- RFA-64cm (accepted)

## Learnings (Actionable)
1. Stateful security components need explicit restart-recovery ACs early.
Action: add a required AC template line for "state/secret continuity across restart" whenever a story repaves or rotates security infrastructure.
Applies to: repave/upgrade/rotation stories.

2. Bash EXIT traps and `set -u` can create false failures when trap code reads local variables.
Action: add shell checklist rule: trap-referenced vars must be global or guarded with defaults; enforce with `bash -n` + failure-path tests.
Applies to: all operational shell scripts.

3. Compose readiness is more reliable through repo-defined targets than raw `docker compose up --wait` in tests.
Action: integration/e2e setup should use `make up` unless a story explicitly tests compose primitives.
Applies to: integration/e2e harnesses.

4. E2E repave validation is strongest when deterministic business-state keys are seeded and verified across both single and full repave.
Action: retain deterministic seed/snapshot checks in demo scripts as a default pattern for resilience demos.
Applies to: future reliability demos.

## Rejection/Block Patterns
- Pattern: architectural ambiguity delayed implementation (keeper shard persistence semantics across repave).
Prevention rule: add an architecture decision checkpoint to stories that modify trust-root/secret material lifecycle before implementation starts.

## Backlog Follow-Ups
- [ ] Update story template: include explicit "restart persistence/recovery" AC language for stateful security services.
- [ ] Add engineering checklist item: avoid trap/local variable coupling in `set -u` scripts.
- [ ] Standardize test harness guidance: prefer `make up` for compose readiness in integration/e2e setup.
