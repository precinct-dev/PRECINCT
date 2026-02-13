# Compose Backport Decision Ledger (v2.4)

This ledger records portability/backport decisions for implemented v2.4 features.
It is not a proprietary runtime pack. It documents what ports cleanly to Compose
and what remains Kubernetes-only.

Classification values:
- `portable`
- `compose-limited`
- `k8s-only`

Machine-readable source of truth:
`docs/architecture/artifacts/compose-backport-decision-ledger.v2.4.json`

## Decision Table

| Feature | Class | Decision Basis |
|---|---|---|
| SPIFFE authentication and mTLS identity | portable | Same SPIFFE/SPIRE identity and gateway auth path in both runtimes |
| Gateway OPA authorization | portable | Same embedded policy enforcement in gateway middleware chain |
| DLP request and response scanning | portable | Same scanner and response firewall middleware behavior |
| Session context and rate limiting | portable | Same KeyDB-backed runtime logic |
| Step-up gating and deep scan | portable | Same middleware decisions and reason-code pathways |
| Tool registry integrity enforcement | portable | Same hash validation and deny-on-mismatch behavior |
| Audit chain emission | portable | Same structured chain-hash emission |
| Response firewall dereference controls | portable | Same outbound policy and handleization path |
| Network segmentation | compose-limited | K8s `NetworkPolicy` has no direct Compose equivalent |
| Pod runtime hardening enforcement | compose-limited | K8s admission/security context enforcement is stronger than Compose |
| Node attestation strength | compose-limited | Local Compose attestation mode is weaker than K8s PSAT |
| Persistent data encryption at rest | compose-limited | K8s encrypted storage classes are stronger than host-level defaults |
| Immutable audit sink delivery | compose-limited | Compose lacks object-lock retention guarantees |
| Sigstore/cosign admission policies | k8s-only | Admission webhook model has no Compose equivalent |
| OPA Gatekeeper admission constraints | k8s-only | Admission-time constraint enforcement is Kubernetes-specific |
| IRSA workload IAM scoping | k8s-only | ServiceAccount IAM federation is Kubernetes-specific |

## Usage

Use this ledger alongside:
- `docs/architecture/k8s-hardening-portability-matrix.md`
- `docs/architecture/non-k8s-cloud-adaptation-guide.md`

If a runtime adaptation changes any class, update the JSON ledger and capture
compensating controls and risk acceptance before release.
