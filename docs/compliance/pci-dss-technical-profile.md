# PCI-DSS Technical Profile Pack

This document defines the optional PCI-DSS technical profile for the reference
architecture. It covers only technical controls that are implemented and
evidenceable from code/runtime artifacts.

## Scope Boundary

- In scope: technical controls, runtime enforcement paths, machine-readable evidence.
- Out of scope: QSA process workflows, legal attestations, and organizational policy operations.

## PCI-DSS Technical Control Mapping

| PCI Profile Control ID | PCI-DSS Requirement(s) | Reference Control Path | Evidence Source |
|---|---|---|---|
| `PCI-AUTH-001` | `8.3.1` | SPIFFE authentication (`spiffe_auth`) | Audit log evidence (`spiffe_id`, request trace) |
| `PCI-AUTHZ-001` | `7.2.1`, `7.2.5` | OPA deny-by-default and least privilege policy | Policy config evidence (`opa-policy.rego`) |
| `PCI-DATA-001` | `3.3.1` | Response firewall deny/tokenize behavior | Response firewall test evidence |
| `PCI-CRYPT-001` | `3.5.1`, `3.6.1` | SPIKE secret/token substitution controls | Redeemer implementation and config evidence |
| `PCI-AUDIT-001` | `10.2.1`, `10.4.1` | Structured audit traceability (`decision_id`, `session_id`) | Audit log evidence |
| `PCI-NET-001` | `1.2.1` | Destination/egress policy controls | OPA policy and destination config evidence |
| `PCI-SC-001` | `6.3.2` | Supply-chain and artifact integrity gate | Configuration and promotion-path evidence |

Source taxonomy:

- `tools/compliance/control_taxonomy.yaml`

## K8s-First Implementation Notes

- Kubernetes is the authoritative production posture for PCI technical controls.
- Immutable and retained audit evidence should come from Kubernetes-backed evidence paths.
- Admission and runtime hardening controls (where present) should be enforced at deployment boundaries before promotion.

## Non-K8s Adaptation Guidance

- Use compensating controls from `docs/architecture/non-k8s-cloud-adaptation-guide.md`.
- Preserve deny-by-default policy enforcement and auditable identity linkage.
- Do not claim parity for controls that rely on Kubernetes-native primitives without equivalent compensating controls and evidence.

## Evidence Outputs

The compliance exporter emits:

- Global evidence bundles:
  - `compliance-evidence.v2.json`
  - `compliance-evidence.v2.csv`
- PCI profile evidence bundles (when PCI rows exist):
  - `compliance-evidence.pci-dss.json`
  - `compliance-evidence.pci-dss.csv`

The PCI bundles are machine-readable subsets filtered to framework `PCIDSS`.
