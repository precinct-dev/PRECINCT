---
id: RFA-tlml
title: "Python SDK docs claim production authentication semantics the client cannot satisfy"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, sdk, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:84e4d10e6ce3daf6ccbd7f61109c2ecc3153068724e5ea9fcc079392e6bbd54b"
follows: [RFA-aszr, RFA-x3ny, RFA-odey]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: The Python SDK presents `spiffe_id` header-based identity as authentication/authorization, but the client has no production mTLS support while gateway prod mode ignores the header.
- Evidence:
  - Gateway prod mode ignores `X-SPIFFE-ID` and requires SPIFFE identity from mTLS client certificate URI SAN: internal/gateway/middleware/spiffe_auth.go:58.
  - Python `GatewayClient` builds a plain `httpx.Client` with no client-cert or custom transport configuration path: sdk/python/mcp_gateway_sdk/client.py:133.
  - README says `spiffe_id` is used for authentication/authorization and shows a prod identity example: sdk/python/README.md:145.
- Impact: The published Python integration path does not match the production zero-trust identity model.

## Acceptance Criteria
1. The Python SDK either supports production-capable mTLS client auth or is explicitly documented and constrained as dev-only.
2. README examples do not imply header-declared identity works in production.
3. Tests/docs cover the supported production integration path.

## Testing Requirements
- Add tests for any new client-cert or custom transport support.
- Add doc validation or example coverage that reflects the final production contract.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of Python SDK client and README vs gateway prod auth behavior.

### proof
- [ ] AC #1: Python SDK production auth story is real and implemented or clearly limited.
- [ ] AC #2: Docs no longer imply prod header-auth support.
- [ ] AC #3: Tests/docs cover the supported production path.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- `sdk/python/README.md` now states that `spiffe_id` is an `X-SPIFFE-ID` header for local/dev gateways only and explicitly says production SPIFFE mTLS client auth is not implemented in this SDK.
- `sdk/python/mcp_gateway_sdk/client.py` enforces gateway-relative model endpoints and keeps the local/dev header-based contract explicit.
- `uv run pytest sdk/python/tests/test_client.py -q -k 'model_chat or ObservabilityRedaction'` (run from `POC/`) -> PASS (`5 passed, 31 deselected in 2.63s`).
- `uv run pytest sdk/python/tests/test_runtime.py -q` (run from `POC/`) -> PASS (`7 passed in 0.02s`).

### proof
- [x] AC #1: The Python SDK is now clearly constrained as a local/dev header-auth client rather than implying unsupported prod mTLS behavior.
- [x] AC #2: README examples no longer imply header-declared identity works in production.
- [x] AC #3: The documented local/dev client path and mediated model helper behavior are covered by the Python SDK tests.

## nd_contract
status: delivered

### evidence
- Verified Python SDK docs now state that `spiffe_id` header auth is for local/dev gateways only and that production SPIFFE mTLS client auth is not implemented in this SDK.
- Verified `call_model_chat()` is documented and implemented as gateway-relative only, preventing direct model URL bypass.
- The shipped docs/tests for this contract live in `sdk/python/README.md`, `sdk/python/mcp_gateway_sdk/client.py`, `sdk/python/tests/test_client.py`, and `sdk/python/tests/test_runtime.py`.
- `python3 -m venv /tmp/poc-sdk-python-venv && . /tmp/poc-sdk-python-venv/bin/activate && pip install -q -e "/Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python[dev]" && pytest /Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python/tests/test_client.py /Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python/tests/test_runtime.py -q` -> PASS (`39 passed in 11.50s`).

### proof
- [x] AC #1: The Python SDK is now explicitly constrained to dev/header-declared identity unless production mTLS support is added later.
- [x] AC #2: README examples no longer imply header-based SPIFFE identity works in production.
- [x] AC #3: SDK docs/tests cover the supported current production contract boundaries.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]], [[RFA-x3ny]], [[RFA-odey]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-tlml against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-tlml` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-tlml` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
