---
id: RFA-gaez
title: "Makefile integration tests default KeyDB to localhost and fail on IPv6 loopback"
status: closed
priority: 0
type: bug
parent: RFA-rlpe
created_at: 2026-03-10T10:56:00Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:a2318fd3151d8268a87951f5d29deb17d088c36af3aebcfe8de55c359b51021c"
labels: [accepted]
follows: [RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: the Makefile integration suite brings up Compose KeyDB successfully, but several tagged integration tests still default their Redis client/CLI URLs to `localhost:6379`.
- Evidence:
  - On March 10, 2026, `make test` failed in the GDPR integration tests with repeated `dial tcp [::1]:6379: connect: connection refused` errors while the Compose KeyDB service was healthy.
  - Docker Compose publishes KeyDB on host IPv4 port 6379, but on this machine `localhost` resolves to IPv6 first for the Redis client, producing a false-negative integration failure.
  - The affected tests are supposed to validate the Makefile-backed local stack, not the host resolver order.
- Impact: `make test` is not reliable across host resolver configurations even when the product stack is healthy.
- Scope: normalize the integration-suite KeyDB defaults to an explicit loopback address (`127.0.0.1`) while preserving `AGW_KEYDB_URL` overrides.

## Acceptance Criteria
1. The tagged integration tests that default to host KeyDB use an explicit IPv4 loopback URL instead of `localhost`.
2. Environment overrides via `AGW_KEYDB_URL` still work unchanged.
3. `make test` passes after the default-host fix.
4. Delivery evidence includes the failing IPv6 localhost symptom and the passing rerun.

## Testing Requirements
- Capture the failing `make test` output showing `[::1]:6379: connect: connection refused`.
- Re-run `make test` after the default-host fix.

## Delivery Requirements
- Append the exact failing and passing commands plus decisive output snippets.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when implementation proof is attached.

## nd_contract
status: new

### evidence
- Created from the March 10, 2026 release sanity rerun after `make test` hit Redis connection failures on `[::1]:6379` while the Compose KeyDB service was healthy.

### proof
- [ ] AC #1: Integration defaults use explicit IPv4 loopback for host KeyDB.
- [ ] AC #2: `AGW_KEYDB_URL` overrides remain supported.
- [ ] AC #3: `make test` passes after the fix.
- [ ] AC #4: Delivery notes include the failing and passing Makefile evidence.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- Original failing Makefile evidence from `/tmp/make-test.log` captured the resolver-dependent Redis false negative: `dial tcp [::1]:6379: connect: connection refused`.
- Normalized the integration-suite host fallback to use explicit IPv4 loopback while preserving `AGW_KEYDB_URL` overrides through `scripts/resolve-keydb-url.sh` and the integration helpers under `internal/agw` and `tests/integration`.
- Final authoritative rerun:
  - `make test > /tmp/make-test-final5.log 2>&1`
  - Result: PASS (full Makefile unit/integration/OPA suite completed successfully on the fixed tree).

## nd_contract
status: delivered

### evidence
- `/tmp/make-test.log` captured the original failure: `dial tcp [::1]:6379: connect: connection refused`.
- `internal/agw/keydb.go`, `internal/agw/keydb_compose.go`, `scripts/resolve-keydb-url.sh`, and `tests/integration/test_helpers_test.go` now preserve explicit IPv4 host fallback plus compose-service fallback while keeping `AGW_KEYDB_URL` overrides intact.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.

### proof
- [x] AC #1: Integration defaults use explicit IPv4 loopback for host KeyDB instead of `localhost`.
- [x] AC #2: `AGW_KEYDB_URL` overrides remain supported.
- [x] AC #3: `make test` passes after the default-host fix.
- [x] AC #4: Delivery notes include the failing IPv6 localhost symptom and the passing rerun.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-gaez against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-gaez` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-gaez` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
