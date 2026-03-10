---
id: RFA-yekm
title: "Gateway body capture breaks session continuity by regenerating session IDs"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T08:44:30Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:cfbd5f954927b1786c8f2c626a61b330b2c5d695e92d61e5370457f1203dbce1"
labels: [release-sanity, robustness, security, session-state, accepted]
follows: [RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Description
## Context (Embedded)
- Problem: During live compose retest of the release demo, step-up escalation never accumulated across repeated requests that intentionally reused the same caller session. The gateway middleware in `internal/gateway/middleware/body_capture.go` generated a fresh internal session ID for each request instead of honoring inbound `X-Session-ID` and `Mcp-Session-Id` headers.
- Evidence:
  - Manual compose replay using repeated `tools/call` requests with the same owner SPIFFE ID and an explicit `X-Session-ID` showed the audit log recording different `session_id` values per request.
  - Because the gateway lost caller session continuity, the escalation counter never crossed the denial threshold and destructive follow-up actions were not blocked by the intended session-aware step-up behavior.
  - After fixing the middleware to preserve inbound session headers and rebuilding the gateway image, the same replay produced a deterministic `403` with `code=stepup_denied` from `middleware=step_up_gating` on the destructive request.
- Impact: Session-aware controls become materially weaker in the live runtime because risk accumulation, escalation, and related audit correlation are fragmented across synthetic per-request sessions. This is both a security regression and a release-credibility issue because the demo path claims session-aware protections that were not actually operating end to end.
- Scope: This story is about preserving externally supplied session identity at the gateway boundary and proving that the real compose stack enforces escalation across multiple requests in one caller session.

## Acceptance Criteria
1. The gateway preserves inbound caller session identity by honoring `X-Session-ID` first, then `Mcp-Session-Id`, and only generates a new session ID when neither header is present.
2. A regression test covers the middleware contract so future refactors cannot silently replace caller-provided session IDs.
3. A real integration test against the running gateway proves that repeated requests in one shared session accumulate step-up state and deny the destructive follow-up with the expected step-up response.
4. Delivery evidence includes the failing live symptom and the passing post-fix replay or equivalent test output.

## Testing Requirements
- Unit: add or update middleware tests for inbound session header preservation.
- Integration: add or update a real `//go:build integration` test that exercises repeated requests against the live gateway with a shared session ID and proves the denial threshold is reached.
- Runtime: reproduce the live compose symptom before the fix if possible, then rerun the replay or `make`-driven validation after the fix.
- Commands to run:
  - `go test ./internal/gateway/middleware -run TestBodyCapture_PreservesIncomingSessionID -count=1`
  - `go test -tags=integration ./tests/integration -run TestStepUpGating_EscalationSessionPersists -count=1 -v`
  - relevant compose or demo command proving the fixed behavior in the real stack

## Delivery Requirements
- Append the exact replay or demo command and the decisive `stepup_denied` evidence.
- Reference the code paths and test paths that enforce the contract.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from release-validation retest after a live compose replay showed step-up escalation failing to accumulate because gateway-generated session IDs replaced caller-provided session IDs.

### proof
- [ ] AC #1: Gateway preserves inbound caller session identity before generating a fallback session ID.
- [ ] AC #2: Middleware regression tests cover inbound session header preservation.
- [ ] AC #3: Live integration coverage proves shared-session escalation reaches the denial path.
- [ ] AC #4: Delivery notes include failing and passing runtime evidence for the session continuity defect.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- The original live symptom was captured in the story context: caller-provided session headers were being replaced, so escalation never accumulated across repeated requests in one session.
- Preserved inbound session identity in the gateway body-capture path before generating fallback session IDs.
- Targeted regression coverage:
  - `go test ./internal/gateway/middleware -run 'TestBodyCapture_PreservesIncomingSessionID' -count=1`
  - Result: PASS (via focused middleware run in this release pass).
  - `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestStepUpGating_EscalationSessionPersists' -count=1 -v`
  - Result: PASS.
- Runtime/demo proof:
  - `/tmp/make-demo-final2.log` includes multiple `stepup_denied` proofs such as `PROOF S-ESC-3` and `PROOF S-ESC-4`, showing the shared-session escalation path now reaches the deny gate.

## nd_contract
status: delivered

### evidence
- `go test ./internal/gateway/middleware -run 'TestBodyCapture_PreservesIncomingSessionID' -count=1` -> PASS.
- `AGW_KEYDB_URL="$(bash scripts/resolve-keydb-url.sh)" go test -tags=integration ./tests/integration -run 'TestStepUpGating_EscalationSessionPersists' -count=1 -v` -> PASS.
- `/tmp/make-demo-final2.log` contains live `stepup_denied` proofs for the escalation scenarios after preserving caller session identity.

### proof
- [x] AC #1: The gateway now honors inbound `X-Session-ID` / `Mcp-Session-Id` before generating a fallback session ID.
- [x] AC #2: Middleware regression tests cover inbound session-header preservation.
- [x] AC #3: Live integration coverage proves shared-session escalation reaches the denial path.
- [x] AC #4: Delivery notes include failing/passing runtime evidence for the session continuity defect.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## Acceptance Criteria


## Design


## Notes


## History


## Links


## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-yekm against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-yekm` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-yekm` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
