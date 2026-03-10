---
id: RFA-j83e
title: "Python SDK observability exports sensitive tool args into insecure traces"
status: closed
priority: 1
type: bug
labels: [release-sanity, security, sdk, observability, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:1fb032b05933ba87bbe2fa5329d7ace7f4feedc56f4a272f64e3939e88dcfa84"
follows: [RFA-aszr, RFA-x3ny, RFA-odey]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: The Python SDK serializes raw tool params into span attributes, and the observability helpers default to insecure/plaintext OTLP transport.
- Evidence:
  - Raw params are serialized into span attributes before the gateway can sanitize or deny the request: sdk/python/mcp_gateway_sdk/client.py:196.
  - README documents JSON-serialized params in spans: sdk/python/README.md:446.
  - Shared helper uses `OTLPSpanExporter(..., insecure=True)`: sdk/python/mcp_gateway_sdk/runtime.py:119.
  - The pydantic demo duplicates insecure OTLP export: agents/pydantic_researcher/agent.py:114.
- Impact: Secrets, prompts, paths, or PII in tool arguments can leak into telemetry, and the default OTLP path is insecure for non-local endpoints.

## Acceptance Criteria
1. Raw tool arguments are redacted or omitted from spans by default.
2. Secure OTLP/TLS is the default for non-local observability, with insecure transport limited to explicit local-dev configuration.
3. Docs/examples describe the telemetry privacy model accurately.

## Testing Requirements
- Add tests for span attribute redaction/default omission.
- Add tests or configuration checks for secure vs explicit-insecure OTLP behavior.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of Python SDK observability paths.

### proof
- [ ] AC #1: Sensitive tool args are not exported raw by default.
- [ ] AC #2: Secure OTLP is default outside explicit local-dev mode.
- [ ] AC #3: Docs/examples match the telemetry privacy posture.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- `sdk/python/mcp_gateway_sdk/client.py` redacts tool-call span payloads by default, exporting only `mcp.tool.arguments_redacted=true` and `mcp.tool.argument_keys=...`.
- `sdk/python/mcp_gateway_sdk/runtime.py` now uses secure OTLP defaults for non-local collectors via `_should_use_insecure_otlp(...)`, with insecure transport limited to explicit local-dev configuration.
- `sdk/python/README.md` documents the redaction model and the local-only insecure OTLP default.
- `uv run pytest sdk/python/tests/test_client.py -q -k 'model_chat or ObservabilityRedaction'` (run from `POC/`) -> PASS (`5 passed, 31 deselected in 2.63s`).
- `uv run pytest sdk/python/tests/test_runtime.py -q` (run from `POC/`) -> PASS (`7 passed in 0.02s`).

### proof
- [x] AC #1: Raw tool arguments are no longer exported into spans by default.
- [x] AC #2: Non-local OTLP exporters default to TLS; insecure transport is limited to explicit local-dev settings.
- [x] AC #3: Docs and tests now match the redaction and OTLP transport posture.

## nd_contract
status: delivered

### evidence
- Verified Python SDK tracing now exports `mcp.tool.arguments_redacted=true` and only `mcp.tool.argument_keys`, omitting raw tool arguments by default.
- Verified shared runtime observability helpers now use insecure OTLP only for explicit local collectors and default to TLS for non-local endpoints.
- The shipped changes live in `sdk/python/mcp_gateway_sdk/runtime.py`, `sdk/python/mcp_gateway_sdk/client.py`, `sdk/python/README.md`, `sdk/python/tests/test_client.py`, and `sdk/python/tests/test_runtime.py`.
- `python3 -m venv /tmp/poc-sdk-python-venv && . /tmp/poc-sdk-python-venv/bin/activate && pip install -q -e "/Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python[dev]" && pytest /Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python/tests/test_client.py /Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/python/tests/test_runtime.py -q` -> PASS (`39 passed in 11.50s`).

### proof
- [x] AC #1: Sensitive tool arguments are no longer exported raw by default.
- [x] AC #2: Secure OTLP defaults apply for non-local collectors unless code explicitly opts into insecure transport.
- [x] AC #3: The Python SDK docs/tests match the telemetry privacy and transport posture.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]], [[RFA-x3ny]], [[RFA-odey]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-j83e against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-j83e` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-j83e` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
