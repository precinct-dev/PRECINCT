# Kubernetes-First Hardening Guide and Compose Portability Matrix

This guide is the Kubernetes-first hardening reference for the Agentic AI Security
Reference Architecture. It is designed to keep control boundaries stable while
documenting exactly where Docker Compose is portable, limited, or not applicable.

Use this document with:
- `docs/architecture/deployment-patterns.md` for detailed rationale
- `docs/architecture/non-k8s-cloud-adaptation-guide.md` for non-K8s compensating-control design
- `docs/deployment-guide.md` for runtime operations
- `docs/ARCHITECTURE.md` ADR-009 for architecture-level invariants
- `docs/architecture/k8s-runtime-validation-campaign.md` for the executed K8s validation checklist
- `docs/architecture/compose-backport-decision-ledger.md` for explicit portability/backport decisions

## Machine-Readable Evidence Artifacts

- K8s runtime validation evidence:
  - Runtime output: `build/validation/k8s-runtime-validation-report.v2.4.json`
  - Checked-in artifact snapshot:
    `docs/architecture/artifacts/k8s-runtime-validation-report.v2.4.json`
- Compose backport decision ledger (machine-readable):
  `docs/architecture/artifacts/compose-backport-decision-ledger.v2.4.json`

## Runtime Class Definitions

- `portable`: same control objective and enforcement path in Kubernetes and Compose.
- `compose-limited`: control objective preserved, but Compose enforcement is weaker and requires compensating checks.
- `k8s-only`: Kubernetes primitive with no Compose-equivalent enforcement; do not claim parity in Compose.

## Control Matrix

| Control | Runtime Class | K8s-First Enforcement | Compose Fallback Behavior | Compensating Checks |
|---|---|---|---|---|
| SPIFFE authentication and mTLS identity | portable | SPIRE-issued SVIDs with workload attestation and mTLS between gateway and services | Same gateway enforcement path; local trust domain and SPIRE socket mount | Run `make k8s-validate` and verify `SPIFFEAuth` coverage in `tests/validate_deployment_patterns.sh` |
| Gateway OPA authorization (tool and path policy) | portable | Embedded OPA middleware policy decisions for every request | Same middleware chain and policy checks | Run gateway tests and confirm deny/allow policy paths in E2E suites |
| DLP request and response scanning | portable | DLP middleware + response firewall scans both directions | Same middleware chain behavior | Run DLP scenarios and verify audit reason codes for denied payloads |
| Session context and rate limiting | portable | KeyDB-backed state and token buckets | Same implementation, endpoint and storage path differ by runtime | Validate session/rate limit behavior in integration tests and conformance reports |
| Step-up gating and deep scan | portable | Risk-based gating + deep scan middleware | Same policy and middleware logic | Validate high-risk tool call and scanner reason-code output |
| Tool registry integrity enforcement | portable | Hash verification and tool allowlist checks in middleware | Same middleware logic | Validate tool registry hash mismatch scenarios |
| Audit chain emission | portable | Structured audit JSON with chain hash for every decision | Same gateway hash-chain emission path | Validate chained audit entries and required correlation fields |
| Response firewall dereference controls | portable | Outbound data handleization and response policy validation | Same middleware behavior | Run response firewall integration checks for allow and deny paths |
| Network segmentation | compose-limited | CNI-enforced default-deny `NetworkPolicy` manifests with explicit gateway egress allowlist (no broad external `:443`) | No CNI policy enforcement in Compose bridge network | Enforce mediated egress controls + strict profile gates and run `make compose-production-intent-validate` (includes deterministic egress negative-path checks) |
| Pod runtime hardening enforcement | compose-limited | Pod Security Admission + restricted security context | Best-effort Dockerfile/runtime flags; no cluster admission reject | Verify non-root, read-only, and dropped capability settings in Compose hardening checks |
| Node attestation strength | compose-limited | `k8s_psat` node attestation with OIDC-backed trust | `join_token` attestation for local/dev environments | Treat Compose as non-production; verify SPIRE entry registration and attestation mode |
| Persistent data encryption at rest | compose-limited | Encrypted PVC/KMS-backed storage for stateful services | Host-level disk encryption only; no runtime-managed PVC encryption | Require host encryption baseline and classify Compose as evaluation-only for regulated workloads |
| Immutable audit sink delivery | compose-limited | Object-lock capable sink (retention mode + retention days + hash chain) | Local audit files/log streams without storage lock guarantees | Use immutable sink validation artifact and mark Compose as non-authoritative retention path |
| Sigstore/cosign admission policies | k8s-only | Admission webhook verifies image signatures before pod admission | No Compose admission interception | Must be satisfied in Kubernetes before production promotion |
| OPA Gatekeeper admission constraints | k8s-only | Cluster admission constraints for image policy and runtime guardrails | No Compose admission layer | Run Gatekeeper constraints in Kubernetes CI and treat Compose as build-time only |
| IRSA workload IAM scoping | k8s-only | ServiceAccount-to-IAM role binding with least privilege | No Compose equivalent identity federation | Enforce secret scoping in gateway policy and use non-production credentials only |

## Compose-Limited Control Boundaries

The following controls are intentionally `compose-limited` and must never be treated as
production-equivalent:

1. Network segmentation
2. Pod runtime hardening enforcement
3. Node attestation strength
4. Persistent data encryption at rest
5. Immutable audit sink delivery

For these controls, Compose can be used for development validation, but release and
audit evidence must come from Kubernetes evidence paths.

## Verification Checklist

Use this checklist before approving an adaptation:

- [ ] Matrix class remains `portable`, `compose-limited`, or `k8s-only` for every listed control.
- [ ] Every `compose-limited` row keeps an explicit fallback behavior and compensating check.
- [ ] No `k8s-only` control is represented as "fully supported" in Compose.
- [ ] `docs/ARCHITECTURE.md` and `docs/deployment-guide.md` link to this guide.
- [ ] Evidence pipeline includes immutable audit sink proof for Kubernetes-backed retention claims.
- [ ] K8s runtime campaign report exists with pass/fail results per major control plane.
- [ ] Backport decision ledger exists for all implemented features.

### Command Validation (K8s-first with Compose fallback)

Run from repository root:

```bash
-n k8s-up
-n up
k8s-validate
k8s-runtime-campaign
bash tests/validate_deployment_patterns.sh
bash tests/e2e/validate_setup_time.sh k8s --dry-run
bash tests/e2e/validate_setup_time.sh compose --dry-run
```

If the local runtime cannot launch Docker or Kubernetes, keep using dry-run validation.
Do not weaken controls to force parity claims.
