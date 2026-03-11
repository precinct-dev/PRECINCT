# Operational SLO/SLI Ownership Matrix

Last Updated: 2026-02-15
Scope: production-intent operational posture for Compose and K8s workflows.

## SLO/SLI Targets

| Service Domain | SLI | SLO Target | Measurement Window |
|---|---|---|---|
| Gateway availability | `/health` success ratio | >= 99.9% | 30 days |
| Policy enforcement | Deny/allow decision correctness on regression suite | 100% critical scenarios | per release campaign |
| Identity path | SPIRE/SPIKE bootstrap success | >= 99.5% successful starts | 30 days |
| Key data durability | KeyDB + SPIKE backup/restore drill success | 100% drill pass | weekly drill cadence |
| Security evidence | Required readiness artifacts present + validated | 100% required artifact completeness | per release campaign |

## Alert Ownership

| Area | Primary Owner | Secondary Owner | Escalation SLA |
|---|---|---|---|
| Gateway runtime errors / availability | Platform On-Call | Security On-Call | 15 minutes |
| SPIRE/SPIKE identity failures | Security On-Call | Platform On-Call | 15 minutes |
| KeyDB/SPIKE backup-restore drill failures | Data Reliability Owner | Platform On-Call | 30 minutes |
| Provenance/attestation gate failures | Release Manager | Security On-Call | 30 minutes |
| CI readiness gate regressions | Release Manager | Platform On-Call | 30 minutes |

## Operational Cadence

- Daily: CI/readiness artifact checks.
- Weekly: backup/restore drill (`make operations-backup-restore-drill`).
- Per release: strict runtime + security evidence + readiness-state validation.

