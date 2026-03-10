---
id: RFA-83an
title: "SPIFFE peer authorization falls back to trust-domain-wide acceptance outside strict profile"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, identity, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:47:59Z
content_hash: "sha256:c3000e32f372a96877b3d1cae61e73a5ada6e036dd63a58ef368a96eb19703a4"
follows: [RFA-aszr, RFA-x3ny, RFA-odey]
closed_at: 2026-03-10T13:47:59Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: Upstream and KeyDB peer authorization degrade to trust-domain-wide acceptance when allowlists are omitted outside strict profiles.
- Evidence:
  - Empty allowlist returns `tlsconfig.AuthorizeAny()`: internal/gateway/spiffe_peer_authorization.go:25.
  - `ENFORCEMENT_PROFILE` defaults to `dev` even though `SPIFFE_MODE` defaults to `prod`: internal/gateway/config.go:278 and internal/gateway/config.go:294.
  - Upstream/KeyDB allowlists only get strict-profile defaults when the profile name is strict: internal/gateway/config.go:280.
- Impact: An operator who enables prod mTLS without also enabling strict profile or explicit pinning can allow any workload in the same trust domain to impersonate those dependencies.

## Acceptance Criteria
1. Production mTLS paths fail closed when upstream/KeyDB peer allowlists are absent.
2. Safe peer pinning defaults are applied whenever `SPIFFE_MODE=prod`, not only when a strict profile string is set.
3. Tests cover missing-allowlist behavior for prod and strict runtime combinations.

## Testing Requirements
- Add unit/integration tests for peer authorization defaults across runtime/profile combinations.
- Verify startup guidance/docs explain the final production pinning requirements.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of SPIFFE peer authorization and runtime config defaults.

### proof
- [ ] AC #1: Prod mTLS fails closed without peer allowlists.
- [ ] AC #2: Safe peer pinning defaults follow prod mode, not only strict profile names.
- [ ] AC #3: Tests cover runtime/profile combinations.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Current gateway config path applies secure peer allowlist defaults whenever `SPIFFE_MODE=prod` via `shouldApplyDefaultSPIFFEPeerAllowlists(...)` in `internal/gateway/spiffe_peer_authorization.go`, not only when the strict profile string is set.
- `internal/gateway/gateway_test.go` now asserts no implicit admin allowlist fallback while still auto-applying upstream/KeyDB SPIFFE peer pinning defaults in prod mode.
- `go test ./internal/gateway -run 'TestConfigFromEnv|TestResolveEnforcementProfile_StrictFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity' -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.978s`).

### proof
- [x] AC #1: Production runtime no longer falls back to trust-domain-wide peer auth when allowlists are omitted; prod mode now supplies pinned upstream/KeyDB SPIFFE defaults before transport wiring.
- [x] AC #2: Safe peer pinning defaults follow `SPIFFE_MODE=prod`, not only strict profile names.
- [x] AC #3: Tests cover the runtime/profile combinations that previously left allowlists empty in prod mode.

## nd_contract
status: delivered

### evidence
- Verified prod-mode SPIFFE peer allowlist defaults now apply whenever `SPIFFE_MODE=prod` via `shouldApplyDefaultSPIFFEPeerAllowlists` in `internal/gateway/spiffe_peer_authorization.go`.
- `go test ./internal/gateway -run "TestResolveEnforcementProfile_StrictFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictStartupFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity" -count=1` -> PASS.
- `go test ./internal/gateway -run "TestConfigFromEnv" -count=1` remains green on the updated env/default behavior.

### proof
- [x] AC #1: Production mTLS paths no longer rely on trust-domain-wide fallback when explicit peer allowlists are absent.
- [x] AC #2: Safe peer pinning defaults are now applied whenever `SPIFFE_MODE=prod`, not only on strict profile names.
- [x] AC #3: Tests cover the strict/prod runtime combinations and missing-allowlist behavior.

## History
- 2026-03-10T13:47:59Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]], [[RFA-x3ny]], [[RFA-odey]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-83an against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-83an` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-83an` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
