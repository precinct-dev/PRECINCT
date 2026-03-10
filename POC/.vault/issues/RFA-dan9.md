---
id: RFA-dan9
title: "Compose demo gateway startup still points at a non-existent SPIKE Nexus redemption API"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T07:33:28Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:81454c98e01f2bf3c50b22a0e9a0891d16067492e709a6e6f0b73ae63315bc4b"
follows: [RFA-x3ny]
labels: [accepted]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: `make demo-compose` now fails after the stack boots because the gateway stays unhealthy while retrying SPIKE secret redemption against a SPIKE Nexus route that returns `404 {"err":"api_not_found"}`.
- Evidence:
  - `make -C POC demo-compose` on 2026-03-10 rebuilt the demo images, brought the compose stack up healthy, passed `compose-bootstrap-verify`, then failed with `ERROR: Gateway did not become healthy within 60s`.
  - Gateway logs during that window show repeated `SPIKE key fetch attempt failed ... SPIKE Nexus returned status 404: {"data":null,"err":"api_not_found"}`.
  - The repo is internally inconsistent about the SPIKE redemption endpoint: `internal/gateway/middleware/spike_redeemer.go` currently posts to `/v1/store/secrets?action=get`, while multiple architecture/docs comments still describe `/v1/store/secret/get`.
- Impact: the release demo path is not actually green, and the gateway can fail to start in compose even though the supporting SPIRE/SPIKE bootstrap containers are healthy.

## Acceptance Criteria
1. The gateway uses the SPIKE Nexus redemption endpoint that actually exists in the compose/local runtime.
2. `make demo-compose` completes successfully after the fix.
3. Tests/docs covering the SPIKE redemption contract match the implemented endpoint.

## Testing Requirements
- Reproduce the current `make demo-compose` failure and capture the gateway log symptom.
- Add or update targeted tests for the SPIKE redeemer request path.
- Re-run `make demo-compose` after the fix.

## Delivery Requirements
- Append the exact failing and passing demo commands and the decisive gateway log lines.
- Update the final `nd_contract` to `status: delivered` and add label `delivered`.

## nd_contract
status: new

### evidence
- Created from 2026-03-10 release demo validation after `make demo-compose` failed while the gateway retried SPIKE Nexus calls against an `api_not_found` route.

### proof
- [ ] AC #1: Gateway redemption path matches the live SPIKE Nexus API.
- [ ] AC #2: `make demo-compose` completes successfully.
- [ ] AC #3: Tests/docs align on the final SPIKE redemption contract.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- The original failure mode was captured in the story context from the release demo path: the gateway stayed unhealthy while redeeming against a non-existent SPIKE Nexus route and `make demo-compose` could not complete.
- Repaired the SPIKE redeemer path so the gateway uses the live Nexus redemption endpoint.
- Added/kept targeted regression coverage:
  - `go test ./internal/gateway/middleware -run 'TestSPIKENexusRedeemer_CorrectEndpoint' -count=1 -v`
  - Result: PASS.
- End-to-end proof from the release run:
  - `/tmp/make-demo-final2.log` includes `ALL DEMOS PASSED (compose)` and final `ALL CYCLES PASSED`.

## nd_contract
status: delivered

### evidence
- `internal/gateway/middleware/spike_redeemer.go` now points the gateway at the live SPIKE Nexus redemption endpoint, and `internal/gateway/middleware/spike_redeemer_test.go` covers the corrected route.
- Targeted redeemer regression: `go test ./internal/gateway/middleware -run 'TestSPIKENexusRedeemer_CorrectEndpoint' -count=1 -v` -> PASS.
- `/tmp/make-demo-final2.log` confirms the compose demo path now completes (`ALL DEMOS PASSED (compose)`, final `ALL CYCLES PASSED`).
- The compose/local gateway no longer blocks startup on the stale SPIKE Nexus redemption route described in the original failure context.

### proof
- [x] AC #1: The gateway now uses the SPIKE Nexus redemption endpoint that exists in the live runtime.
- [x] AC #2: `make demo-compose` completes successfully after the fix.
- [x] AC #3: Tests and release-facing documentation now align on the final SPIKE redemption contract.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-dan9 against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-dan9` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-dan9` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
