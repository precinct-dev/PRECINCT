# Security Event Response Runbook

Last Updated: 2026-02-15
Scope: unauthorized access attempts, attestation/provenance failures, policy bypass attempts.

## 1. Event Intake

- Capture timestamp, triggering detector, affected environment, and suspected blast radius.
- Create/attach incident story in `nd` and assign incident commander + security lead.

## 2. Immediate Verification

```bash
make promotion-identity-validate
make compose-production-intent-validate
make strict-runtime-validate
```

## 3. Containment

```bash
# Isolate external ingress path if needed
docker compose stop precinct-gateway

# Preserve current logs before restarting components
docker compose logs --timestamps > build/security-event/compose.log
```

## 4. Forensic Collection

```bash
make production-readiness-validate
make readiness-state-validate
docker compose logs --timestamps precinct-gateway spike-nexus keydb > build/security-event/core-services.log
```

## 5. Recovery + Hardening Validation

```bash
make ci-gate-parity-validate
make compose-production-intent-preflight
make demo-compose
```

## 6. Closure Requirements

- Root cause documented.
- Control gap remediations captured as backlog stories.
- Post-incident review added to `nd` evidence/proof notes.
