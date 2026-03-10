---
id: RFA-xsy7
title: "Integration release suite still assumes external OPA health and legacy tool/step-up contracts"
status: closed
priority: 0
type: bug
labels: [release-sanity, testing, robustness, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T12:15:41Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:3810d48d6991a862b0291c3f77df2eb96e05a0b857e28ec9cdc3f5b7a395b62c"
follows: [RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Description
## Context (Embedded)
- Problem: the Makefile-first integration suite still contained several tests written against older runtime assumptions after the gateway hardening work landed.
- Evidence:
  - On March 10, 2026, a fresh `make test` rerun progressed deep into `tests/integration` and then failed in `tests/integration/step_up_gating_integration_test.go` and `tests/integration/tool_registry_test.go`.
  - The failures expected legacy response shapes (`error`, `reason`, `risk_breakdown` at top level), waited for a standalone `OPA_URL/health` surface that no longer gates the embedded OPA runtime, and used path / tool expectations that do not match the current live compose contract.
  - Focused repros showed the live gateway returning the newer v24 error envelope (`code`, `middleware`, `details.gate`, `details.risk_breakdown`) and allowing / denying requests according to runtime-valid `/app/*` paths plus embedded OPA.
- Impact: `make test` can fail after the real product fixes are in place because stale release-suite assertions are checking superseded contracts instead of genuine regressions.
- Scope: align the affected integration tests with the current embedded-OPA runtime and step-up/tool-registry envelope so `make test` reflects real release risk.

## Acceptance Criteria
1. The affected integration tests no longer depend on `OPA_URL/health` as a readiness gate when embedded OPA is the live runtime contract.
2. Step-up response-format assertions match the current v24 gateway error envelope and verify the gate / risk details under `details`.
3. Tool-registry integration tests use runtime-valid allow cases and continue to prove deny cases for hash mismatch, unknown tools, destination denial, and poisoning checks.
4. Delivery evidence includes the failing `make test` snippets and the passing focused rerun(s).

## Testing Requirements
- Reproduce the stale-test failures from `make test` and capture the decisive failure lines.
- Run focused integration coverage for the repaired step-up and tool-registry cases.
- Re-run the Makefile release suite after the test-contract fix if feasible.

## Delivery Requirements
- Append exact failing and passing commands plus decisive output snippets.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from the March 10, 2026 release sanity rerun after `make test` exposed stale integration expectations for embedded OPA readiness, step-up response shape, and tool-registry live-contract cases.

### proof
- [ ] AC #1: Integration tests stop depending on external OPA health when embedded OPA is authoritative.
- [ ] AC #2: Step-up response assertions match the v24 error envelope.
- [ ] AC #3: Tool-registry allow/deny cases reflect the current live runtime contract.
- [ ] AC #4: Delivery notes include failing `make test` lines and the passing focused rerun.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes Addendum
- A subsequent full `make test` rerun exposed one final stale integration cluster in `tests/integration/response_firewall_integration_test.go`. The live runtime was correctly requiring approval-capability tokens for approval-band sensitive tool calls, and the old public-tool case was still using a path/tool combination that the host-based harness no longer authorizes.
- Repaired `tests/integration/response_firewall_integration_test.go` to mint real approval tokens through `/admin/approvals/request` + `/admin/approvals/grant`, bind them to the test session, and use a low-risk `messaging_status` call for the public-response path.
- Passing focused rerun after the repair:
  - `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestResponseFirewall_(SensitiveToolReturnsHandle|DereferenceWithSameSPIFFEID|DereferenceAfterExpiry|DereferenceWithDifferentSPIFFEID|PublicToolRawResponse)$' -v -count=1`\n  - Result: PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 3.123s`).\n\n## nd_contract\nstatus: delivered\n\n### evidence\n- `/tmp/make-test-final4.log` captured the last stale response-firewall failures: `TestResponseFirewall_SensitiveToolReturnsHandle`, `TestResponseFirewall_DereferenceWithSameSPIFFEID`, `TestResponseFirewall_DereferenceAfterExpiry`, `TestResponseFirewall_DereferenceWithDifferentSPIFFEID`, and `TestResponseFirewall_PublicToolRawResponse` were asserting pre-hardening behavior.\n- `tests/integration/response_firewall_integration_test.go` now uses real approval-capability lifecycle calls plus a current low-risk public tool path.\n- `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestResponseFirewall_(SensitiveToolReturnsHandle|DereferenceWithSameSPIFFEID|DereferenceAfterExpiry|DereferenceWithDifferentSPIFFEID|PublicToolRawResponse)$' -v -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 3.123s`).\n\n### proof\n- [x] AC #1: The repaired integration tests no longer depend on deprecated embedded-OPA / pre-approval shortcut assumptions.\n- [x] AC #2: Response-firewall sensitive-tool assertions now follow the current approval-capability contract.\n- [x] AC #3: Public-response coverage uses a live low-risk tool path the current harness authorizes.\n- [x] AC #4: Delivery notes include the failing `make test` lines and the passing focused rerun(s).

## Delivery Notes Addendum
- A later full `make test` rerun uncovered one more stale embedded-OPA assumption in `tests/integration/walking_skeleton_test.go`: `TestWalkingSkeleton` still failed with `OPA not ready: service http://localhost:8181/health not ready after 30s` from `/tmp/make-test-final3.log`.
- Repaired `tests/integration/walking_skeleton_test.go` to stop waiting on standalone OPA, use the live runtime path `/app/gateway`, and send the current `read` tool hash so the audit assertions exercise the actual tool-registry contract.
- Passing focused rerun after the repair:
  - `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestWalkingSkeleton(Negative)?$' -v -count=1`\n  - Result: PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 0.890s`).\n\n## nd_contract\nstatus: delivered\n\n### evidence\n- `/tmp/make-test-final3.log` captured the remaining stale walking-skeleton failure: `TestWalkingSkeleton` -> `OPA not ready: service http://localhost:8181/health not ready after 30s`.\n- `tests/integration/walking_skeleton_test.go` now aligns to the embedded-OPA/runtime-valid tool-registry contract.\n- `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestWalkingSkeleton(Negative)?$' -v -count=1` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 0.890s`).\n\n### proof\n- [x] AC #1: The repaired integration tests no longer depend on `OPA_URL/health` when embedded OPA is authoritative.\n- [x] AC #2: Step-up / walking-skeleton contract assertions now match the current live gateway behavior and nested security envelope.\n- [x] AC #3: Tool-registry / walking-skeleton integration cases use runtime-valid allow inputs instead of stale host-path assumptions.\n- [x] AC #4: Delivery notes include the failing `make test` lines and the passing focused rerun(s).

## Delivery Notes
- Failing release-suite evidence from `/tmp/make-test-final.log` before the repair:
  - `TestStepUpGating_ResponseFormat` expected legacy top-level fields (`error`, `reason`, `gate`, `risk_score`, `risk_breakdown`) but the live gateway returned the current v24 envelope: `{"code":"authz_policy_denied", ... "middleware":"opa_policy", "details":{"reason":"tool_not_authorized"}}`.
  - `TestToolHashVerification/ValidHashAllowed` and `/NoHashProvided` failed with `Expected allowed request, got 403` because the test used stale runtime inputs.
  - `TestPathBasedRestrictions`, `TestDestinationRestrictions`, and `TestStepUpGating` failed waiting for `OPA_URL/health` even though the compose stack now uses embedded OPA.
  - `TestPoisoningPatternDetection/CleanTool` failed with `Expected clean tool to be allowed, got 403` because the test used a path that is not valid in the live container runtime.
- Repaired `tests/integration/step_up_gating_integration_test.go` so the response-format assertion checks the current v24 step-up envelope (`code`, `middleware`, `middleware_step`, `details.gate`, `details.risk_score`, `details.risk_breakdown`).
- Repaired `tests/integration/tool_registry_test.go` so it:
  - stops depending on `OPA_URL/health`,
  - uses runtime-valid allow cases under `/app/*`,
  - uses the current `read` tool hash from `config/tool-registry.yaml`, and
  - asserts live allow/deny behavior for destination blocking, step-up denial, unknown tools, and poisoning checks.
- Passing focused rerun:
  - `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestStepUpGating_ResponseFormat|TestToolHashVerification|TestPathBasedRestrictions|TestDestinationRestrictions|TestStepUpGating$|TestPoisoningPatternDetection' -v`
  - Result: PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 1.037s`).

## nd_contract
status: delivered

### evidence
- `make test` exposed stale release-suite assumptions in `tests/integration/step_up_gating_integration_test.go` and `tests/integration/tool_registry_test.go` around embedded OPA readiness, step-up response shape, and runtime-valid allow cases.
- Updated the failing tests to the current live compose contract instead of weakening product behavior.
- `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestStepUpGating_ResponseFormat|TestToolHashVerification|TestPathBasedRestrictions|TestDestinationRestrictions|TestStepUpGating$|TestPoisoningPatternDetection' -v` -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/tests/integration 1.037s`).

### proof
- [x] AC #1: The repaired integration tests no longer depend on `OPA_URL/health` when embedded OPA is authoritative.
- [x] AC #2: Step-up response assertions now verify the current v24 error envelope and nested risk details.
- [x] AC #3: Tool-registry integration cases use runtime-valid allow inputs and still prove deny paths for hash mismatch, unknown tools, destination denial, and poisoning checks.
- [x] AC #4: Delivery notes include the failing `make test` snippets and the passing focused rerun.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-xsy7 against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-xsy7` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-xsy7` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
