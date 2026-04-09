# Gateway Bypass Case-26 Conformance

## Scope

Case 26 in both SDK demos verifies that agent traffic cannot bypass gateway controls for remote-skill/model paths.

## Runtime Contract

- Compose (`DEMO_STRICT_DEEPSCAN=1`):
  - direct model-provider egress must be blocked.
  - case 26 must pass through strict fail-closed outcomes only.
  - non-strict timeout variance marker is not allowed.
- K8s/non-strict:
  - gateway-mediated model route outcomes may include timeout variance.
  - timeout variance is accepted only in non-strict mode and only for case-26 model-route call.

## SDK Parity Requirement

Go and Python demos must implement the same case-26 acceptance surface:

- pass on explicit gateway-controlled statuses (`400/401/403/429/502/503`)
- pass on non-strict timeout variance
- fail on unexpected non-gateway errors in strict mode

## Validator

Use:

- `bash tests/e2e/validate_gateway_bypass_case26.sh`

The validator enforces:

- strict/non-strict timeout guard presence in both SDK implementations
- compose strict-path behavior (no timeout-variance marker)
- pass/fail parity for case 26 in both SDK demos across Compose and K8s logs
