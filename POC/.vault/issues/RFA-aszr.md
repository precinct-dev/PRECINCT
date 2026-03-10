---
id: RFA-aszr
title: "OPA policy hot reload accepts unsigned policy changes"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T07:08:21Z
content_hash: "sha256:c0e89a977b4e81804b0118b4514afa4aca0408681474c7420a95ccada25a60fd"
closed_at: 2026-03-10T07:08:21Z
close_reason: "Accepted: OPA reload attestation enforcement and verified/rejected admin reload evidence independently confirmed"
led_to: [RFA-mnw2, RFA-7lrd, RFA-4oss, RFA-83an, RFA-phtc, RFA-j83e, RFA-tlml, RFA-565d, RFA-k87w, RFA-896s, RFA-sn2j]
---

## Description
## Context (Embedded)
- Problem: OPA policies can be reloaded from disk without attestation or signature verification.
- Evidence:
  - OPA engine starts a watcher on the policy directory with no attestation configuration: internal/gateway/middleware/opa_engine.go:63 and internal/gateway/middleware/opa_engine.go:558.
  - `Reload()` just reloads policy/data files from disk: internal/gateway/middleware/opa_engine.go:304.
  - Admin reload endpoint calls `g.opa.Reload()` directly and only reports `CosignVerified` for the registry side: internal/gateway/gateway.go:1937.
- Impact: The core authorization policy surface can be modified live despite adjacent release claims around signed control artifacts.

## Acceptance Criteria
1. Strict/prod policy reloads are signature-verified or otherwise attested before activation.
2. Unsigned or tampered OPA policy changes are rejected and leave the prior policy active.
3. Admin reload responses and audit evidence distinguish verified policy reload from rejected unsigned changes.

## Testing Requirements
- Add unit/integration coverage for accepted signed reload and rejected unsigned/tampered reload.
- Verify non-strict/dev behavior is explicitly documented if any compatibility mode remains.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of OPA engine and admin reload path.

### proof
- [ ] AC #1: Strict/prod OPA reloads require verification.
- [ ] AC #2: Unsigned/tampered policy updates are rejected safely.
- [ ] AC #3: Reload responses/audit logs reflect verification outcome.

## Acceptance Criteria


## Design


## Notes
## PM Decision
ACCEPTED [2026-03-10]: Independent verification confirms strict OPA reloads are attested before activation, rejected unsigned/tampered updates preserve the previous policy, and admin reload responses plus audit evidence distinguish verified vs rejected outcomes.

## nd_contract
status: accepted

### evidence
- Reviewed delivered proof and spot-checked implementation wiring in `internal/gateway/config.go`, `internal/gateway/enforcement_profile.go`, `internal/gateway/gateway.go`, and `internal/gateway/middleware/opa_engine.go`.
- Verified docs now document `OPA_POLICY_PUBLIC_KEY` plus dev-vs-strict OPA reload behavior in `docs/configuration-reference.md` and `docs/deployment-guide.md`.
- `rg -n "OPAPolicyPublicKey|PolicyReloadPublicKeyPEM|ReadFile\(cfg\.OPAPolicyPublicKey\)|opa_policy_public_key" internal/gateway`.
- `rg -n 'TODO|panic\\("todo"\\)|NotImplementedError|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/enforcement_profile_test.go internal/gateway/enforcement_profile_integration_test.go internal/gateway/gateway_test.go internal/gateway/middleware/opa_engine_test.go docs/configuration-reference.md docs/deployment-guide.md` -> no matches.
- `go test -v ./internal/gateway -run ^TestResolveEnforcementProfile_StrictFailsWithoutOPAPolicyPublicKey -count=1` -> PASS.
- `go test -v ./internal/gateway/middleware -run 'TestOPAEngineReload_AttestationEnabled_(SignedUpdateAccepted|UnsignedUpdateRejectedPreservesOldPolicy|TamperedUpdateRejectedPreservesOldPolicy)$' -count=1` -> PASS.
- `go test -v ./internal/gateway -run ^TestAdminPolicyReload -count=1` -> PASS.

### proof
- [x] AC #1: Strict profiles require `OPA_POLICY_PUBLIC_KEY`, `Gateway.New` wires that key into `OPAEngine`, and signed reloads report verified attestation before activation.
- [x] AC #2: Unsigned and tampered OPA reloads are rejected and the previous policy remains active, proven by targeted `OPAEngine` reload tests.
- [x] AC #3: `TestAdminPolicyReload` proves `opa_verified`, `opa_verification_mode`, rejection fields, and `policy.opa.reload` audit evidence distinguish verified vs rejected reloads.

## Implementation Evidence (DELIVERED)

### Files Changed
- internal/gateway/enforcement_profile_test.go
- internal/gateway/enforcement_profile_integration_test.go
- internal/gateway/gateway_test.go
- internal/gateway/middleware/opa_engine_test.go
- docs/configuration-reference.md
- docs/deployment-guide.md

### Commands Run
- `gofmt -w internal/gateway/enforcement_profile_test.go internal/gateway/enforcement_profile_integration_test.go internal/gateway/gateway_test.go internal/gateway/middleware/opa_engine_test.go`
- `go test ./internal/gateway -run 'TestResolveEnforcementProfile_StrictPassesWithStrongApprovalSigningKey|TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey|TestEnforcementProfile_StrictStartupFailsWithUnsignedToolRegistry|TestEnforcementProfile_StrictStartupFailsWhenDestinationAllowlistFallbackWouldBeUsed|TestEnforcementProfile_StrictStartupFailsWhenRiskThresholdFallbackWouldBeUsed|TestMCPTransportHTTPClient_StrictRequiresSPIFFETLS|TestAdminPolicyReload|TestConfigFromEnv' -count=1`
- `go test ./internal/gateway/middleware -run 'TestOPAEngineHotReload|TestOPAEngineReload_AttestationEnabled_' -count=1`
- `go test ./internal/gateway/... -count=1`
- `rg -n 'TODO|panic\\("todo"\\)|NotImplementedError|unimplemented!|raise NotImplementedError|return \\{\\}|pass$' internal/gateway/enforcement_profile_test.go internal/gateway/enforcement_profile_integration_test.go internal/gateway/gateway_test.go internal/gateway/middleware/opa_engine_test.go docs/configuration-reference.md docs/deployment-guide.md`

### Test Results
- `go test ./internal/gateway -run ... -count=1` PASS
- `go test ./internal/gateway/middleware -run ... -count=1` PASS
- `go test ./internal/gateway/... -count=1` PASS
- Stub scan returned no matches in touched files.

### Notes
- Strict-profile fixtures now provide a per-test signed tool-registry fixture plus the required `OPA_POLICY_PUBLIC_KEY`, so strict tests assert intended startup behavior without depending on shared repo signature state.
- Added OPA reload tests for signed acceptance plus unsigned/tampered rejection while preserving the previously active policy.
- Added admin reload tests covering `opa_verified`, `opa_verification_mode`, rejection fields, and `policy.opa.reload` audit evidence.
- Updated operator docs to document `OPA_POLICY_PUBLIC_KEY` and the dev-vs-strict OPA reload behavior.
- No commit was created because the worktree already contains unrelated in-progress changes on the current branch; only the story-relevant files above were modified.

## nd_contract
status: delivered

### evidence
- Updated strict-profile test fixtures to set `OPA_POLICY_PUBLIC_KEY` and to use per-test signed tool-registry fixtures.
- Added gateway admin reload coverage for verified and rejected OPA reload responses plus audit logging.
- Added middleware OPA reload coverage for signed acceptance and unsigned/tampered rejection with old-policy preservation.
- `go test ./internal/gateway -run 'TestResolveEnforcementProfile_StrictPassesWithStrongApprovalSigningKey|TestEnforcementProfile_StrictStartupPassesWithStrongApprovalSigningKey|TestEnforcementProfile_StrictStartupFailsWithUnsignedToolRegistry|TestEnforcementProfile_StrictStartupFailsWhenDestinationAllowlistFallbackWouldBeUsed|TestEnforcementProfile_StrictStartupFailsWhenRiskThresholdFallbackWouldBeUsed|TestMCPTransportHTTPClient_StrictRequiresSPIFFETLS|TestAdminPolicyReload|TestConfigFromEnv' -count=1` -> PASS.
- `go test ./internal/gateway/middleware -run 'TestOPAEngineHotReload|TestOPAEngineReload_AttestationEnabled_' -count=1` -> PASS.
- `go test ./internal/gateway/... -count=1` -> PASS.
- Stub scan across touched files returned no matches.

### proof
- [x] AC #1: Strict/prod OPA reloads require verification via `OPA_POLICY_PUBLIC_KEY`, and signed reloads report verified attestation in gateway/admin tests.
- [x] AC #2: Unsigned or tampered OPA policy updates are rejected and the previous policy remains active, proven by new OPA engine reload tests.
- [x] AC #3: Admin reload responses and audit evidence now distinguish verified reloads from rejected unsigned changes, proven by `TestAdminPolicyReload` response and audit assertions.

## nd_contract
status: in_progress

### evidence
- Claimed continuation: 2026-03-10
- Read story AC and existing partial edits in config, enforcement profile, gateway, and OPA engine.

### proof
- [ ] AC #1: Strict/prod OPA reloads require verification.
- [ ] AC #2: Unsigned/tampered policy updates are rejected safely.
- [ ] AC #3: Reload responses/audit logs reflect verification outcome.

## nd_contract
status: in_progress

### evidence
- Claimed: 2026-03-09

### proof
- [ ] AC #1: Strict/prod OPA reloads require verification.
- [ ] AC #2: Unsigned/tampered policy updates are rejected safely.
- [ ] AC #3: Reload responses/audit logs reflect verification outcome.

## History
- 2026-03-10T07:08:21Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Led to: [[RFA-mnw2]], [[RFA-7lrd]], [[RFA-4oss]], [[RFA-83an]], [[RFA-phtc]], [[RFA-j83e]], [[RFA-tlml]], [[RFA-565d]], [[RFA-k87w]], [[RFA-896s]], [[RFA-sn2j]]

## Comments

## nd_contract
status: accepted

### evidence
- Final authoritative acceptance contract appended at EOF because `nd update --append-notes` placed the earlier PM acceptance block before older contracts in `## Notes`.
- Story status is closed and labels are `release-sanity`, `security`, `accepted`.
- Independent verification remained the same:
  - `go test -v ./internal/gateway -run '^TestResolveEnforcementProfile_StrictFailsWithoutOPAPolicyPublicKey$' -count=1` -> PASS.
  - `go test -v ./internal/gateway/middleware -run 'TestOPAEngineReload_AttestationEnabled_(SignedUpdateAccepted|UnsignedUpdateRejectedPreservesOldPolicy|TamperedUpdateRejectedPreservesOldPolicy)$' -count=1` -> PASS.
  - `go test -v ./internal/gateway -run '^TestAdminPolicyReload$' -count=1` -> PASS.

### proof
- [x] AC #1: Strict profiles require `OPA_POLICY_PUBLIC_KEY`, `Gateway.New` wires that key into `OPAEngine`, and signed reloads are attested before activation.
- [x] AC #2: Unsigned and tampered OPA reloads are rejected while the previously active policy remains in force.
- [x] AC #3: Admin reload responses and audit evidence distinguish verified reloads from rejected unsigned changes.
