---
id: RFA-mnw2
title: "Gateway seeds an active compose-webhook connector in all runtimes"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:49Z
content_hash: "sha256:bb608d71e4039ebf5a670ea9b9f7cab3e76bcdfd6036c64f97fb19e3140573c8"
follows: [RFA-k7l5, RFA-odey, RFA-aszr, RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: Connector authority initializes with an already-active `compose-webhook` connector.
- Evidence:
  - `newConnectorConformanceAuthority()` seeds `compose-webhook` with a hard-coded dev SPIFFE principal and `connectorStateActive`: internal/gateway/connector_authority.go:96.
- Impact: A trust relationship is pre-activated before the declared register/validate/approve/activate governance flow.

## Acceptance Criteria
1. Production and strict paths start with no pre-activated connector state.
2. Any dev/demo bootstrap connector is explicitly scoped to local demo mode and cannot leak into production-intent startup.
3. Tests verify startup state for both local demo and strict/prod modes.

## Testing Requirements
- Add tests for connector authority initialization across runtime modes.
- Verify compose demo scenarios still work via explicit demo bootstrap, not global seeded active state.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of connector authority initialization.

### proof
- [ ] AC #1: No pre-activated connector exists in strict/prod startup.
- [ ] AC #2: Demo bootstrap is mode-scoped and explicit.
- [ ] AC #3: Initialization tests cover both local demo and production-intent modes.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Removed the globally seeded active `compose-webhook` connector from `newConnectorConformanceAuthority()` in `internal/gateway/connector_authority.go`.
- Updated initialization/status expectations in `internal/gateway/connector_authority_test.go` and `internal/gateway/phase3_wiring_test.go`.
- `go test ./internal/gateway -run 'TestConnector(AuthorityStartsWithoutSeededConnector|LifecycleTransitions|EndpointsAndIngressEnforcement|MutationEndpointsRequireAdminAuthorization)|TestV24RuntimeDispatch_WiresAllEntrypointFamilies' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.722s`).

### proof
- [x] AC #1: Strict/prod startup no longer contains a pre-activated connector record.
- [x] AC #2: Any demo bootstrap connector must now be registered explicitly through the lifecycle flow instead of leaking from global startup state.
- [x] AC #3: Startup and wiring tests cover the empty-start behavior that replaces the old seeded connector assumption.

## nd_contract
status: delivered

### evidence
- Removed the globally seeded active `compose-webhook` connector from `internal/gateway/connector_authority.go` so startup begins without pre-activated connector state.
- Updated startup/wiring tests to expect explicit lifecycle-driven connector creation instead of a baked-in active connector.
- `go test ./internal/gateway -run "TestConnectorAuthorityStartsWithoutSeededConnector|TestV24RuntimeDispatch_WiresAllEntrypointFamilies" -count=1` -> PASS.
- `go test -tags=integration ./tests/integration -run "TestConnectorLifecycleMutationsRequireAdminAuthorization" -count=1` -> PASS with explicit registration flow.

### proof
- [x] AC #1: Strict/prod startup no longer includes a pre-activated connector.
- [x] AC #2: Demo/bootstrap behavior now depends on explicit lifecycle actions instead of global seeded state.
- [x] AC #3: Tests cover the no-seeded-connector startup contract.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-k7l5]], [[RFA-odey]], [[RFA-aszr]], [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-mnw2 against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-mnw2` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-mnw2` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
