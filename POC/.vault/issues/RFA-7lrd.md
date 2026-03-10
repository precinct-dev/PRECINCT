---
id: RFA-7lrd
title: "Connector lifecycle mutations on /v1/connectors require only identity, not admin authorization"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:49Z
content_hash: "sha256:fad0675387bd433868f7cfce82f69573c80433d7ae03ce30d514ce312b609458"
follows: [RFA-aszr, RFA-odey, RFA-k7l5, RFA-x3ny]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: Connector lifecycle mutations ride the `/v1/*` bypass path and require only SPIFFE identity, not admin authorization.
- Evidence:
  - OPA bypass contract treats all `/v1/*` routes as `spiffe_identity_required` only: internal/gateway/middleware/opa_bypass_contracts.go:52.
  - Connector lifecycle routes are handled under `/v1/connectors/*`: internal/gateway/connector_authority.go:355.
  - `register`, `validate`, `approve`, `activate`, and `revoke` execute lifecycle mutations with no admin gate: internal/gateway/connector_authority.go:428.
- Impact: Any authenticated workload can mutate connector trust state and promote its own ingress connector.

## Acceptance Criteria
1. Connector lifecycle mutation routes require explicit admin authorization and are no longer protected by identity-only bypass rules.
2. Non-admin identities cannot register, approve, activate, or revoke connectors.
3. Tests cover positive admin flow and negative non-admin flow for every mutating connector endpoint.

## Testing Requirements
- Add integration tests for `/v1/connectors/register|validate|approve|activate|revoke` with admin and non-admin identities.
- Verify status/report endpoints still behave as intended after tightening authz.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of OPA bypass contracts and connector handler code.

### proof
- [ ] AC #1: Mutating connector routes enforce admin authorization.
- [ ] AC #2: Non-admin identities are denied for connector lifecycle mutation.
- [ ] AC #3: Integration tests cover all mutating endpoints.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Tightened connector mutation authz in `internal/gateway/connector_authority.go` and `internal/gateway/middleware/opa_bypass_contracts.go` so `/v1/connectors/register|validate|approve|activate|revoke` require explicit admin authorization while report/status remain identity-only.
- Added targeted admin/non-admin coverage in `internal/gateway/connector_authority_test.go` and integration coverage in `tests/integration/connector_lifecycle_authz_integration_test.go`.
- `go test ./internal/gateway -run 'TestConnector(AuthorityStartsWithoutSeededConnector|LifecycleTransitions|EndpointsAndIngressEnforcement|MutationEndpointsRequireAdminAuthorization)|TestV24RuntimeDispatch_WiresAllEntrypointFamilies' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.722s`).
- `go test -tags=integration ./tests/integration -run 'TestConnectorLifecycleMutationsRequireAdminAuthorization|TestIngressSubmitConnectorConformanceReplayAndFreshness|TestPhase3WalkingSkeleton_AllPlanesAllowAndDeny|TestDiscordAdapter_SPIFFEAuth_Denial' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 1.848s`).

### proof
- [x] AC #1: Mutating connector routes now enforce admin authorization instead of the generic identity-only bypass.
- [x] AC #2: Non-admin identities are denied for connector lifecycle mutations while admin flows remain allowed.
- [x] AC #3: Unit and integration tests cover the mutating connector endpoints plus the read-only status/report behavior.

## nd_contract
status: delivered

### evidence
- Tightened `/v1/connectors/*` bypass rules so mutating routes require explicit admin authorization while read-only routes remain identity-gated.
- Removed identity-only mutation path handling from connector authority and enforced admin authz in `internal/gateway/connector_authority.go`.
- `go test ./internal/gateway -run "TestConnectorMutationEndpointsRequireAdminAuthorization|TestV24RuntimeDispatch_WiresAllEntrypointFamilies" -count=1` -> PASS.
- `go test -tags=integration ./tests/integration -run "TestConnectorLifecycleMutationsRequireAdminAuthorization" -count=1` -> PASS.

### proof
- [x] AC #1: Mutating connector routes now enforce admin authorization instead of identity-only bypass.
- [x] AC #2: Non-admin identities are denied for connector lifecycle mutation requests.
- [x] AC #3: Integration and unit coverage exercise the admin and non-admin mutation paths.

## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]], [[RFA-odey]], [[RFA-k7l5]], [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-7lrd against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-7lrd` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-7lrd` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
