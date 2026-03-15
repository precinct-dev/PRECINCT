# OpenClaw Secure-Port Control Ownership Matrix

Last Updated: 2026-02-16  
Scope: ownership and SLO responsibilities for OpenClaw wrapper control surfaces.

| Control Domain | Primary Owner | Secondary Owner | SLO / Escalation Target | Evidence Source |
|---|---|---|---|---|
| Authn (SPIFFE identity admission) | Security On-Call | Platform On-Call | Incident ack <= 15 min | gateway audit + SPIRE entry checks |
| Authz (tool/model/control decisions) | Security Policy Owner | Platform On-Call | Policy deny regression triage <= 30 min | OPA decision logs + integration suites |
| Policy bundle integrity | Security Policy Owner | Release Manager | Rollback decision <= 30 min | bundle digest checks + campaign reports |
| Audit chain/provenance | Security Compliance Owner | Platform On-Call | Missing correlation investigation <= 30 min | audit JSONL hash-chain + decision_id/trace_id checks |
| Egress and destination controls | Platform On-Call | Security On-Call | Unauthorized egress containment <= 15 min | destination allowlist validation + E2E deny checks |
| Approvals and step-up lifecycle | Security Approvals Owner | Platform On-Call | Approval workflow incident response <= 30 min | approval API traces + denial harness |

## Operational Cadence

- Per release: run OpenClaw wrapper campaign + comparative report update.
- Weekly: run OpenClaw incident/rollback drill and attach artifact set.
- Daily: monitor deny reason-code drift and SPIRE registration readiness.
