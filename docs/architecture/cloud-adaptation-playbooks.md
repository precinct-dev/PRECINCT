# Cloud Adaptation Playbooks (AWS, GCP, Azure)

This document provides step-by-step adaptation playbooks to reproduce the same
security outcomes validated in local Kubernetes-in-Docker and Compose, but on
managed cloud runtimes.

Use this with:
- `docs/architecture/k8s-hardening-portability-matrix.md`
- `docs/architecture/non-k8s-cloud-adaptation-guide.md`
- `docs/architecture/cloudflare-workers-compensating-controls.md`
- `docs/deployment-guide.md`

## Scope

- In scope: AWS (EKS managed nodes and EKS with Fargate), GCP (GKE), Azure (AKS).
- Goal: preserve control invariants (identity, policy, DLP, audit chain, supply-chain).
- Non-goal: one-click IaC templates for every cloud account layout.

## Common Prerequisites

1. Create cloud accounts/projects/subscriptions and networking baselines.
2. Install tools: `kubectl`, `kustomize`, `helm`, `cosign`, `jq`.
3. Clone repo and set working dir:
```bash
cd /path/to/PRECINCT/POC
```
4. Define target context variables:
```bash
export CLUSTER_CONTEXT=<your-cloud-k8s-context>
export ENV_OVERLAY=staging   # or prod
```

## Shared Validation Bar (All Providers)

A provider adaptation is considered aligned only when all of the following are true:

1. Identity is workload-bound (no static long-lived service credentials for gateway paths).
2. Admission and policy controls are fail-closed for production workloads.
3. Audit chain remains tamper-evident and retained to immutable storage.
4. DLP, response firewall, and token substitution controls are active in live traffic.
5. Runtime segmentation and egress controls are enforced and evidenced.

---

## AWS Playbook

### Path A: EKS (Managed Node Groups)

1. Provision EKS cluster with managed node groups and OIDC enabled.
2. Install cluster prerequisites:
```bash
kubectl --context "${CLUSTER_CONTEXT}" apply -f infra/eks/crds/policy-controller-crds.yaml
kubectl --context "${CLUSTER_CONTEXT}" apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.16.0/deploy/gatekeeper.yaml
```
3. Configure workload identity and IAM bindings (IRSA or equivalent) for:
   - gateway
   - policy controller components
   - telemetry/audit sinks
4. Configure immutable audit destination (S3 Object Lock) and retention policy.
5. Deploy chosen overlay:
```bash
kubectl --context "${CLUSTER_CONTEXT}" apply -k "infra/eks/overlays/${ENV_OVERLAY}"
```
6. Register SPIRE entries and verify identities are issued.
7. Run validation suite:
```bash
make k8s-validate
make strict-runtime-validate
make observability-evidence-gate-validate
```
8. Run campaign and collect artifacts:
```bash
make k8s-runtime-campaign
```
9. Evidence gate: record cluster metadata, command outputs, and artifact paths.

### Path B: EKS + Fargate

Fargate can run many workloads here, but some controls need explicit adaptation.

1. Provision EKS with:
   - Fargate profile(s) for app namespaces
   - small managed node group for components that require daemon/node-level behavior
2. Keep Gatekeeper/policy-controller on node-group capacity unless fully validated on Fargate.
3. For identity controls:
   - preserve workload identity federation and short-lived credentials
   - if SPIRE agent deployment model differs, document compensating identity controls
4. Validate network segmentation and egress controls at both SG/NACL and K8s policy levels.
5. Deploy overlays and run the same validation/evidence commands as Path A.
6. Add a compensating-control note for any control that cannot be implemented identically on Fargate.

Acceptance rule: do not mark parity if a control is downgraded without documented compensating controls and residual-risk approval.

---

## GCP Playbook (GKE)

1. Provision GKE cluster with Workload Identity enabled.
2. Install Gatekeeper and required CRDs (policy controller equivalents for signature policy as needed).
3. Bind GCP IAM service accounts to Kubernetes service accounts for least privilege.
4. Configure immutable audit retention path (Cloud Storage bucket with retention lock).
5. Deploy overlay:
```bash
kubectl --context "${CLUSTER_CONTEXT}" apply -k "infra/eks/overlays/${ENV_OVERLAY}"
```
6. Validate:
```bash
make k8s-validate
make strict-runtime-validate
make observability-evidence-gate-validate
```
7. Run runtime campaign and save evidence artifacts.
8. Confirm egress restrictions (VPC firewall + K8s policy) and admission fail-closed behavior.

---

## Azure Playbook (AKS)

1. Provision AKS with Microsoft Entra workload identity enabled.
2. Install Gatekeeper/constraint templates and signature-policy CRDs equivalent.
3. Configure managed identity bindings for workload service accounts.
4. Configure immutable audit retention path (Blob immutability policy).
5. Deploy overlay:
```bash
kubectl --context "${CLUSTER_CONTEXT}" apply -k "infra/eks/overlays/${ENV_OVERLAY}"
```
6. Validate:
```bash
make k8s-validate
make strict-runtime-validate
make observability-evidence-gate-validate
```
7. Run runtime campaign and publish machine-readable/human-readable evidence.
8. Verify segmentation, outbound allowlists, and policy fail-closed controls.

---

## Production Sign-Off Checklist

- [ ] Identity control is workload-bound and short-lived.
- [ ] Admission and image trust controls are fail-closed.
- [ ] Audit evidence is immutable and retained by policy.
- [ ] DLP/response/token controls are active in live flows.
- [ ] Segmentation and egress controls are enforced and tested.
- [ ] Runtime campaign artifacts are published and reproducible.
- [ ] Residual risks are explicitly documented and accepted.
