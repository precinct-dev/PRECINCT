---
id: RFA-quga
title: "Local K8s demo gateway trust-domain drift resolves demo SPIFFE IDs as anonymous"
status: closed
priority: 0
type: bug
labels: [release-sanity, robustness, k8s, identity, demo, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T08:56:37Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:964a54262828306357b709a219229f6502cafec9b85226b93774398fd33bdc4f"
follows: [RFA-x3ny]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: the local Kubernetes demo path uses header-declared demo identities under `spiffe://poc.local/...`, but the local overlay configured the gateway with `SPIFFE_MODE=dev` and `SPIFFE_TRUST_DOMAIN=agentic-ref-arch.poc`.
- Evidence:
  - During `make demo` on 2026-03-10, the Kubernetes Go and Python demos failed broadly with `403` / `code=principal_level_insufficient` at OPA step 6, even for baseline happy-path tavily requests that pass in Docker Compose.
  - Direct repro against the forwarded K8s gateway returned `403 principal_level_insufficient` for `tools/call(tavily_search)` when the request carried `X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev`.
  - Gateway audit logs for those requests showed `spiffe_id="spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"`, `principal_level":5`, and `principal_role":"anonymous"`, proving principal resolution failed before OPA evaluation.
  - The local overlay deployment rendered `SPIFFE_MODE=dev` with `SPIFFE_TRUST_DOMAIN=agentic-ref-arch.poc`, so `PrincipalHeaders` compared the header-declared demo identities against the cluster trust domain and downgraded them to anonymous.
- Impact: `make demo` is not actually green end to end for the Kubernetes path, and the local release-validation workflow can report false policy regressions across most K8s demo scenarios.

## Acceptance Criteria
1. The local K8s demo gateway resolves the canonical header-declared demo identities under `spiffe://poc.local/...` to their intended principal roles instead of `anonymous`.
2. `make demo` completes successfully for the Kubernetes path after the trust-domain alignment fix.
3. Validation or documentation covering the local K8s demo wiring makes the trust-domain expectation explicit so this drift is caught before release validation.

## Testing Requirements
- Reproduce the failing `make demo` K8s behavior and capture at least one decisive `principal_level_insufficient` failure plus the corresponding audit-log `principal_level=5` / `principal_role=anonymous` evidence.
- Re-run `make demo` after the fix and capture the successful K8s demo result.
- Add or update validation/docs so the local K8s demo trust-domain contract is machine-checkable or clearly documented.

## Delivery Requirements
- Append the failing and passing commands, plus the decisive gateway/audit evidence, to this story's notes.
- Update the final `nd_contract` to `status: delivered` and add label `delivered` when the implementation is complete.

## nd_contract
status: new

### evidence
- Created from 2026-03-10 release-validation debugging after the Kubernetes leg of `make demo` downgraded `spiffe://poc.local/...` demo identities to `anonymous` due to local overlay trust-domain drift.

### proof
- [ ] AC #1: Local K8s demo identities under `spiffe://poc.local/...` resolve to the intended principal roles.
- [ ] AC #2: `make demo` passes for the Kubernetes demo path.
- [ ] AC #3: The local K8s demo trust-domain contract is documented or validated so the drift is caught pre-release.

## Acceptance Criteria


## Design


## Notes
## Delivery Notes
- Captured the failing local-K8s trust-domain symptom from `/tmp/demo-k8s-run-2.log`:
  - repeated audit events for `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` showed `principal_level":5` and `principal_role":"anonymous"`.
- Aligned the local K8s overlay with the canonical `poc.local` dev demo identity contract and added explicit validation coverage.
- Re-ran the dedicated validation surface:
  - `bash tests/e2e/validate_local_demo_identity_wiring.sh`
  - Result: PASS (`local K8s demo identity wiring matches the canonical poc.local dev demo contract`).
- End-to-end proof:
  - `/tmp/make-demo-final2.log` includes `ALL DEMOS PASSED (k8s)` and final `ALL CYCLES PASSED`.
  - `/tmp/make-k8s-validate-final.log` also includes `Validating local K8s demo identity wiring...` followed by `[PASS] local K8s demo identity wiring matches the canonical poc.local dev demo contract`.

## nd_contract
status: delivered

### evidence
- `/tmp/demo-k8s-run-2.log` captured the original drift symptom with `principal_role":"anonymous"` for canonical `spiffe://poc.local/...` demo identities.
- `bash tests/e2e/validate_local_demo_identity_wiring.sh` -> PASS.
- `/tmp/make-demo-final2.log` shows the K8s demo path green end to end.
- `/tmp/make-k8s-validate-final.log` confirms the machine-checkable identity-wiring validation passes.

### proof
- [x] AC #1: Local K8s demo identities under `spiffe://poc.local/...` now resolve to their intended roles instead of `anonymous`.
- [x] AC #2: `make demo` passes for the Kubernetes demo path.
- [x] AC #3: The local K8s demo trust-domain contract is now validated explicitly before release sign-off.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-x3ny]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-quga against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-quga` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-quga` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
