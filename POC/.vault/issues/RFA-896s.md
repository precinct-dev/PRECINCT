---
id: RFA-896s
title: "Validation harness and strict-startup integration tests drift after release hardening"
status: closed
priority: 0
type: bug
labels: [release-sanity, robustness, quality-gates, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T07:14:19Z
created_by: ramirosalas
updated_at: 2026-03-10T13:47:59Z
content_hash: "sha256:0b93b7b2404d37e675ab48451d9f250f9390cdb97fb7bddb7730f6ea4b10e216"
follows: [RFA-x3ny, RFA-aszr]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: Make-based integration validation still contains stale assumptions after the admin allowlist and OPA policy attestation hardening landed.
- Evidence:
  - `tests/conformance/harness/harness.go` builds an in-memory gateway for ruleops/admin fixtures without `AdminAuthzAllowedSPIFFEIDs`, so admin fixture cases now fail with `authz_policy_denied`.
  - `tests/integration/model_trust_startup_integration_test.go` expects guard-artifact digest mismatch to be the first strict startup failure, but the config no longer satisfies the stricter prerequisites (`ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS`, `OPA_POLICY_PUBLIC_KEY`).
  - `tests/integration/opa_bypass_contract_integration_test.go` expects bypass-contract validation to be the first strict startup failure, but the same missing strict prerequisites now fail earlier.
- Impact: `make test` is red even though the hardened behavior is correct, which blocks release confidence and hides whether the real security stories are actually stable.

## Acceptance Criteria
1. Make-backed integration validation passes with the current strict/admin hardening in place.
2. The conformance harness uses an authorized admin identity when exercising admin ruleops fixtures.
3. Strict-startup integration tests satisfy all unrelated strict prerequisites so they fail on the intended condition only.

## Testing Requirements
- Run the affected targeted integration tests.
- Re-run `make test` or the integration package path that previously failed.

## nd_contract
status: new

### evidence
- 2026-03-10 `make test` failed after gateway/unit suites passed.
- 2026-03-10 targeted failures reproduced in `TestConformanceHarness_FixtureCoverageAndOutcomes`, `TestGatewayStartupFailsClosedOnGuardArtifactDigestMismatch`, and `TestStrictStartupFailsWhenOPABypassContractMissingChecks`.

### proof
- [ ] AC #1: Make-backed integration validation is green again.
- [ ] AC #2: Conformance harness admin fixtures run with an authorized admin identity.
- [ ] AC #3: Strict-startup tests isolate their intended fail-closed assertion.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Updated `tests/conformance/harness/harness.go` and integration helpers (`tests/integration/admin_identity_test.go`, `tests/integration/test_helpers_test.go`, `tests/integration/distributed_state_multi_instance_test.go`) so admin fixture paths use an explicitly authorized admin SPIFFE ID.
- Updated strict-startup integration inputs in `tests/integration/model_trust_startup_integration_test.go` and `tests/integration/opa_bypass_contract_integration_test.go` so unrelated strict prerequisites are satisfied before asserting the intended fail-closed condition.
- `go test -tags=integration ./tests/integration -run 'TestGatewayStartupFailsClosedOnGuardArtifactDigestMismatch|TestStrictStartupFailsWhenOPABypassContractMissingChecks|TestDistributedState_MultiInstanceApprovalAndBreakGlass' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 1.444s`).
- `make test` -> PASS (full Makefile unit/integration/OPA gate green again; final OPA summary `PASS: 73/73`).

### proof
- [x] AC #1: The Make-backed validation path is green again with the hardened admin/strict prerequisites in place.
- [x] AC #2: The conformance/integration harness now exercises admin flows with an authorized identity.
- [x] AC #3: Strict-startup integration tests fail on their intended hardening condition instead of earlier unrelated prerequisites.

## nd_contract
status: delivered

### evidence
- Updated strict-startup fixtures and integration helpers so admin hardening and OPA policy attestation prerequisites are satisfied before each targeted failure assertion.
- Added shared admin SPIFFE test helper coverage for integration packages and repaired strict-startup test fixtures under `tests/integration` and `tests/conformance/harness`.
- `go test -tags=integration ./tests/integration -run "TestGatewayStartupFailsClosedOnGuardArtifactDigestMismatch|TestStrictStartupFailsWhenOPABypassContractMissingChecks|TestConformanceHarness_FixtureCoverageAndOutcomes" -count=1` -> PASS.
- `make -C /Users/ramirosalas/workspace/agentic_reference_architecture/POC test` -> PASS.

### proof
- [x] AC #1: Make-backed integration validation is green again with the current hardening in place.
- [x] AC #2: Conformance/admin fixture paths now run under an authorized admin identity.
- [x] AC #3: Strict-startup tests now fail on their intended fail-closed condition only.

## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]], [[RFA-aszr]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-896s against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-896s` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-896s` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
