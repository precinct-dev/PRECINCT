# Compose Signature Credential Injection Runbook

## Purpose

Provide secure operator steps to supply registry credentials for compose live signature verification without committing secrets to source control.

## Rules

- Never commit `COMPOSE_PROD_REGISTRY_TOKEN` or equivalent credential values.
- Use short-lived tokens where possible.
- Rotate credentials after release campaigns according to platform policy.

## Required Environment Variables

- `COMPOSE_PROD_REGISTRY_USERNAME`
- `COMPOSE_PROD_REGISTRY_TOKEN`
- `COMPOSE_PROD_VERIFY_SIGNATURE=1`

## Operator Procedure

1. Obtain short-lived registry credentials from the platform security workflow.
2. Export credentials only in the current shell session:

```bash
export COMPOSE_PROD_REGISTRY_USERNAME="<registry-user>"
export COMPOSE_PROD_REGISTRY_TOKEN="<registry-token>"
export COMPOSE_PROD_VERIFY_SIGNATURE=1
```

3. Execute strict preflight:

```bash
make compose-production-intent-preflight
```

4. Remove credentials after campaign:

```bash
unset COMPOSE_PROD_REGISTRY_USERNAME
unset COMPOSE_PROD_REGISTRY_TOKEN
unset COMPOSE_PROD_VERIFY_SIGNATURE
```

## Validation

Run deterministic prerequisite validator:

```bash
bash tests/e2e/validate_compose_signature_prereqs.sh
```
