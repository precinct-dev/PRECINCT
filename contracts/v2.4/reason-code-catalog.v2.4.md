# PRECINCT Gateway Reason-Code Catalog v2.4

This file defines the reason-code governance policy for contract set `2.4.0`.
Machine-readable entries are stored in `reason-code-catalog.v2.4.json`.

## Stability Rules

- Reason-code identifiers are immutable once released.
- Semantic meaning is stable per code and tied to control-plane behavior.
- Additive growth is allowed through minor versions.
- Reuse of retired identifiers is prohibited.

## Semantic Taxonomy

Reason-code meaning is determined by prefix + suffix:

- Prefix families:
  - `INGRESS_*`: ingress admission and source/freshness checks.
  - `MODEL_*`: mediated model egress governance.
  - `PROMPT_SAFETY_*`: regulated-content and prompt-safety actions.
  - `CONTEXT_*`: context admission, provenance, and memory boundaries.
  - `LOOP_*`: immutable loop governance limits and halts.
  - `TOOL_*`: tool capability, adapter, and action gating.
  - `RLM_*`: recursive loop manager governance.
  - `CONTRACT_*`: payload contract and plane consistency checks.

- Suffix families:
  - `*_ALLOW`: permit outcome.
  - `*_DENIED`, `*_BLOCKED`, `*_INVALID`: deny outcome.
  - `*_REQUIRED`: required precondition (often step-up/approval).
  - `*_APPLIED`: mitigation/override action applied.
  - `HALT_*`: loop termination boundary reached.

Prompt-safety operational alignment for v2.4:

- `PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED` is emitted for raw regulated prompt content in HIPAA profile mode.
- `PROMPT_SAFETY_TOKENIZATION_APPLIED` is emitted when `prompt_action=tokenize` requests minimum-necessary tokenization.
- `PROMPT_SAFETY_REDACTION_APPLIED` is emitted when `prompt_action=redact` requests minimum-necessary redaction.

## Deprecation Policy

- Deprecation requires a replacement code and a one-minor-version overlap period.
- Deprecated codes remain parseable in SDKs until next major version.
- Deprecation metadata fields:
  - `status`: `active` or `deprecated`
  - `deprecated_in`: version string or `null`
  - `replacement_code`: code string or `null`

## Source Of Truth

- Code constants: `POC/internal/gateway/phase3_contracts.go`
- Frozen catalog: `POC/contracts/v2.4/reason-code-catalog.v2.4.json`
