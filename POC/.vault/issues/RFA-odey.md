---
id: RFA-odey
title: "Admin allowlist defaults to baked-in dev/test principals when unset"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T07:08:11Z
content_hash: "sha256:b168a9ef9673f5c0fe6f08061d6f1a7bc0bb380270b83efca8bb2c5fc0b73bf2"
closed_at: 2026-03-10T07:08:11Z
close_reason: "Accepted: admin authz no longer defaults to baked-in dev/test principals; strict startup fails closed and targeted gateway verification passed"
led_to: [RFA-mnw2, RFA-7lrd, RFA-565d, RFA-83an, RFA-phtc, RFA-tlml, RFA-j83e]
---

## Description
## Context (Embedded)
- Problem: Admin authorization silently falls back to baked-in dev/test SPIFFE IDs when `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` is unset.
- Evidence:
  - Fallback happens unconditionally in config loading: internal/gateway/config.go:274.
  - Default allowlist includes `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` and generic test identities: internal/gateway/config.go:414.
  - In dev mode, admin auth can source identity directly from `X-SPIFFE-ID`: internal/gateway/admin_authz.go:58.
  - Integration test shows header-based admin success for the dspy researcher identity: tests/integration/gateway_admin_authz_integration_test.go:47.
- Impact: A misconfigured deployment can grant `/admin/*` access to non-operator identities; dev quickstarts make this spoofable over headers.

## Acceptance Criteria
1. No implicit admin principals are applied outside explicit test-only code paths.
2. Strict/prod startup fails closed when the admin allowlist is missing or empty.
3. Integration coverage verifies that baked-in dev/test identities cannot reach `/admin/*` in production-intent configurations.

## Testing Requirements
- Add/update tests covering missing allowlist behavior in prod and strict profiles.
- Verify existing dev/test flows use explicit test configuration instead of hidden defaults.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of config/authz code and admin integration tests.

### proof
- [ ] AC #1: No non-test default admin principals remain.
- [ ] AC #2: Strict/prod fails closed on missing admin allowlist.
- [ ] AC #3: Integration tests cover the production-intent behavior.

## Acceptance Criteria


## Design


## Notes
## PM Decision
ACCEPTED [2026-03-10]: Evidence reviewed and independently verified with narrow reruns. Admin authz no longer applies implicit runtime defaults, strict startup fails closed without an explicit allowlist, and production-intent coverage denies the dev researcher identity unless explicitly allowlisted.

## nd_contract
status: accepted

### evidence
- Reviewed delivered proof in `nd show RFA-odey` and confirmed the story carried the required delivered evidence, AC mapping, and targeted command history.
- `vlt vault="Claude" search query="agentic reference architecture POC gateway admin authz"` -> no matching prior vault notes.
- Static verification of the delivered surfaces:
  - `rg -n "adminAuthzAllowedSPIFFEIDs|ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS|dspy-researcher/dev|test-admin|test-operator|fallback|default.*admin|admin allowlist" internal/gateway tests/integration docker-compose.strict.yml docs/configuration-reference.md docs/deployment-guide.md`
  - `sed -n "240,460p" internal/gateway/config.go`
  - `sed -n "1,260p" internal/gateway/enforcement_profile.go`
  - `sed -n "1,260p" internal/gateway/enforcement_profile_integration_test.go`
  - `sed -n "1,260p" tests/integration/admin_identity_test.go`
  - `sed -n "520,575p" internal/gateway/gateway.go`
  - `sed -n "1,120p" internal/gateway/admin_authz.go`
  - `sed -n "1,120p" internal/gateway/phase3_test_helpers_test.go`
  - `sed -n "380,455p" internal/gateway/gateway_test.go`
  - `sed -n "1,240p" tests/integration/gateway_admin_authz_integration_test.go`
  - `sed -n "1,260p" tests/integration/test_helpers_test.go`
  - `sed -n "1,240p" tests/integration/ruleops_lifecycle_integration_test.go`
  - `sed -n "1,220p" tests/integration/distributed_state_multi_instance_test.go`
- Stub scan across delivered files returned no matches: `rg -n "NotImplementedError|panic\(\s*\"todo\"|unimplemented!\(|raise NotImplementedError|\bTODO\b|return \{\}|^\s*pass\s*$" internal/gateway/config.go internal/gateway/gateway.go internal/gateway/enforcement_profile.go internal/gateway/enforcement_profile_test.go internal/gateway/enforcement_profile_integration_test.go internal/gateway/gateway_test.go internal/gateway/phase3_test_helpers_test.go tests/integration/admin_identity_test.go tests/integration/test_helpers_test.go tests/integration/distributed_state_multi_instance_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/gateway_admin_circuit_breakers_integration_test.go tests/integration/gateway_admin_circuit_breakers_reset_integration_test.go tests/integration/gateway_admin_policy_reload_integration_test.go tests/integration/agw_policy_test_runtime_integration_test.go docker-compose.strict.yml docs/configuration-reference.md docs/deployment-guide.md`.
- Independent targeted rerun passed: `go test ./internal/gateway -run "TestConfigFromEnv|TestEnforcementProfile_StrictStartupFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity"` -> `ok   github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.554s`.
- Parent epic check: `nd children RFA-rlpe --json` shows other children remain open/in_progress, so the epic stays open.

### proof
- [x] AC #1: Runtime config/gateway wiring no longer injects implicit admin SPIFFE principals; only explicit test fixtures set allowlists for dev/integration flows.
- [x] AC #2: Strict/prod startup fails closed when `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` is missing or empty, verified by the targeted strict-startup test rerun.
- [x] AC #3: Production-intent coverage denies the baked-in dev researcher identity unless it is explicitly allowlisted, verified by the targeted strict-prod authz test rerun and supporting fixture inspection.

## Implementation Evidence (DELIVERED)

### Files Changed
- internal/gateway/config.go
- internal/gateway/gateway.go
- internal/gateway/enforcement_profile.go
- internal/gateway/enforcement_profile_test.go
- internal/gateway/enforcement_profile_integration_test.go
- internal/gateway/gateway_test.go
- internal/gateway/phase3_test_helpers_test.go
- tests/integration/admin_identity_test.go
- tests/integration/test_helpers_test.go
- tests/integration/distributed_state_multi_instance_test.go
- tests/integration/ruleops_lifecycle_integration_test.go
- tests/integration/gateway_admin_circuit_breakers_integration_test.go
- tests/integration/gateway_admin_circuit_breakers_reset_integration_test.go
- tests/integration/gateway_admin_policy_reload_integration_test.go
- tests/integration/agw_policy_test_runtime_integration_test.go
- docker-compose.strict.yml
- docs/configuration-reference.md
- docs/deployment-guide.md

### CI/Test Results
- Commands run:
  - `gofmt -w internal/gateway/config.go internal/gateway/gateway.go internal/gateway/enforcement_profile.go internal/gateway/enforcement_profile_test.go internal/gateway/enforcement_profile_integration_test.go internal/gateway/gateway_test.go internal/gateway/phase3_test_helpers_test.go tests/integration/admin_identity_test.go tests/integration/test_helpers_test.go tests/integration/distributed_state_multi_instance_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/gateway_admin_circuit_breakers_integration_test.go tests/integration/gateway_admin_circuit_breakers_reset_integration_test.go tests/integration/gateway_admin_policy_reload_integration_test.go tests/integration/agw_policy_test_runtime_integration_test.go tests/integration/gateway_admin_authz_integration_test.go`
  - `go test ./internal/gateway -run 'TestV24RuleOpsErrorsUseUnifiedGatewayEnvelope|TestV24ProxySpanAttributesForEndpointEntries|TestConfigFromEnv|TestResolveEnforcementProfile_StrictFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictStartupFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity'`
  - `go test -tags=integration tests/integration/gateway_admin_authz_integration_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/test_helpers_test.go tests/integration/admin_identity_test.go -run 'TestGatewayAdminAuthzIntegration'`
  - `go test -tags=integration tests/integration/distributed_state_multi_instance_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/test_helpers_test.go tests/integration/admin_identity_test.go -run 'TestDistributedState_MultiInstanceApprovalAndBreakGlass'`
  - `go vet ./...`
- Summary: targeted gateway/admin unit PASS, targeted integration PASS, distributed-state regression PASS, vet PASS.
- Key output:
  - `ok   github.com/RamXX/agentic_reference_architecture/POC/internal/gateway 0.787s`
  - `ok   command-line-arguments 0.710s`
  - `ok   command-line-arguments 0.767s`
  - `go vet ./...` exited 0.

### Branch / Commit
- Branch: `codex/RFA-x3ny`
- Commit: not created in this delivery because the shared worktree already contained unrelated in-flight changes and the fix was delivered in-place per instruction to preserve them.

### Wiring
- Admin allowlist defaults removed from runtime config loading and gateway construction; only explicit config now reaches `Gateway.adminAuthzAllowedSPIFFEIDs`.
- Strict profile startup now rejects missing/empty `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` before the gateway can start in production-intent mode.
- Dev/integration admin paths now set their allowlisted principal explicitly in test fixtures instead of inheriting hidden defaults.

### AC Verification
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | No implicit admin principals are applied outside explicit test-only code paths. | `internal/gateway/config.go`, `internal/gateway/gateway.go`, `internal/gateway/phase3_test_helpers_test.go`, `tests/integration/admin_identity_test.go`, `tests/integration/ruleops_lifecycle_integration_test.go`, `tests/integration/distributed_state_multi_instance_test.go` | `internal/gateway/gateway_test.go`, `internal/gateway/v24_horizontal_hardening_test.go` | PASS |
| 2 | Strict/prod startup fails closed when the admin allowlist is missing or empty. | `internal/gateway/enforcement_profile.go` | `internal/gateway/enforcement_profile_test.go`, `internal/gateway/enforcement_profile_integration_test.go` | PASS |
| 3 | Integration coverage verifies baked-in dev/test identities cannot reach `/admin/*` in production-intent configurations. | `internal/gateway/enforcement_profile_integration_test.go`, `docker-compose.strict.yml`, `docs/configuration-reference.md`, `docs/deployment-guide.md` | `internal/gateway/enforcement_profile_integration_test.go`, `tests/integration/gateway_admin_authz_integration_test.go` | PASS |

## nd_contract
status: delivered

### evidence
- Runtime fallback to baked-in admin SPIFFE IDs removed from `internal/gateway/config.go` and `internal/gateway/gateway.go`.
- Strict profile validation now enforces `admin_authz_allowed_spiffe_ids` in `internal/gateway/enforcement_profile.go`.
- Explicit admin allowlists were added to internal/dev integration fixtures (`internal/gateway/phase3_test_helpers_test.go`, `tests/integration/ruleops_lifecycle_integration_test.go`, `tests/integration/distributed_state_multi_instance_test.go`) and shared helper `tests/integration/admin_identity_test.go` was added so `go vet ./...` sees the symbol without integration-only build tags.
- Docs/config updates now require `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` for strict compose/deployment flows (`docker-compose.strict.yml`, `docs/configuration-reference.md`, `docs/deployment-guide.md`).
- Verification commands passed: `go test ./internal/gateway -run 'TestV24RuleOpsErrorsUseUnifiedGatewayEnvelope|TestV24ProxySpanAttributesForEndpointEntries|TestConfigFromEnv|TestResolveEnforcementProfile_StrictFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictStartupFailsWithoutAdminAllowlist|TestEnforcementProfile_StrictProdDeniesDevResearcherAdminIdentity'`, `go test -tags=integration tests/integration/gateway_admin_authz_integration_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/test_helpers_test.go tests/integration/admin_identity_test.go -run 'TestGatewayAdminAuthzIntegration'`, `go test -tags=integration tests/integration/distributed_state_multi_instance_test.go tests/integration/ruleops_lifecycle_integration_test.go tests/integration/test_helpers_test.go tests/integration/admin_identity_test.go -run 'TestDistributedState_MultiInstanceApprovalAndBreakGlass'`, and `go vet ./...`.

### proof
- [x] AC #1: Gateway startup/runtime no longer injects hidden admin principals; only explicit test fixtures set allowlists where intended.
- [x] AC #2: Strict profile validation rejects missing or empty admin allowlists before startup.
- [x] AC #3: Production-intent admin authz coverage now proves the dev researcher identity is denied unless explicitly allowlisted, and strict deployment docs/config require explicit admin identities.

## nd_contract
status: in_progress

### evidence
- Claimed in /Users/ramirosalas/workspace/agentic_reference_architecture/POC on 2026-03-10.
- Context gathered from `nd show RFA-odey`, `vlt vault="Claude" search query="agentic reference architecture POC gateway admin authz"` (no matching notes), and code inspection of admin authz/config/enforcement profile surfaces.
- Existing workspace already had unrelated in-flight changes on branch `codex/RFA-x3ny`; preserving them per instructions while limiting edits to this story's scope.

### proof
- [ ] AC #1: No non-test default admin principals remain.
- [ ] AC #2: Strict/prod fails closed on missing admin allowlist.
- [ ] AC #3: Integration tests cover the production-intent behavior.

## nd_contract
status: in_progress

### evidence
- Coordinating assignment: 2026-03-10
- Story queued for developer implementation on admin authz/config/test surfaces.

### proof
- [ ] AC #1: No non-test default admin principals remain.
- [ ] AC #2: Strict/prod fails closed on missing admin allowlist.
- [ ] AC #3: Integration tests cover the production-intent behavior.

## History
- 2026-03-10T07:08:11Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Led to: [[RFA-mnw2]], [[RFA-7lrd]], [[RFA-565d]], [[RFA-83an]], [[RFA-phtc]], [[RFA-tlml]], [[RFA-j83e]]

## Comments
