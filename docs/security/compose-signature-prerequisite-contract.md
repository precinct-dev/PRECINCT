# Compose Live Signature Prerequisite Contract

## Purpose

Define mandatory prerequisites for fail-closed live signature verification in compose production-intent release mode.

This contract supports `RFA-l6h6.8.10` by ensuring strict signature mode fails early and clearly when trust/auth inputs are missing.

## Required Inputs

| Input | Description | Owner |
|---|---|---|
| `COMPOSE_PROD_VERIFY_SIGNATURE=1` | Enables live signature verification mode | Release Engineer |
| `COMPOSE_PROD_REGISTRY_USERNAME` | Registry principal for pulling/verifying required images | Platform Security |
| `COMPOSE_PROD_REGISTRY_TOKEN` | Registry token with least-privilege access for verification | Platform Security |
| Policy file (`config/compose-production-intent-policy.json`) | Trusted identity regex + issuer constraints | Security Engineering |

## Fail-Closed Behavior

When live signature mode is enabled:

1. Missing credential inputs fail immediately with actionable errors.
2. Registry authentication failure is treated as release validation failure.
3. Signature verification failure for required services fails the campaign.
4. No silent skip path is permitted.

## Command

```bash
COMPOSE_PROD_VERIFY_SIGNATURE=1 make compose-production-intent-preflight
```

Use `bash tests/e2e/validate_compose_signature_prereqs.sh` to validate deterministic missing-prerequisite failure behavior.

## Runbook

Credential injection and handling requirements are documented in:

- `docs/operations/runbooks/compose-signature-credential-injection.md`
