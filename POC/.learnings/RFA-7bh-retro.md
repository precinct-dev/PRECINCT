# Epic RFA-7bh Retrospective: Local K8s -- Full Stack on Docker Desktop kubeadm

**Date:** 2026-02-06
**Stories:** RFA-7bh.1, RFA-7bh.2
**Outcome:** Both stories accepted on first delivery. Zero rejections.

## Epic Summary

Delivered complete Kustomize overlay infrastructure for deploying the full agentic security gateway stack to Docker Desktop kubeadm. RFA-7bh.1 created the local overlay with all services (gateway, SPIRE, SPIKE Nexus, KeyDB, OTel Collector) fitting within 4 CPU / 8GB RAM laptop constraints. RFA-7bh.2 added sigstore/policy-controller admission webhook for cosign signature verification, complementing OPA Gatekeeper for supply chain security.

## What Went Well

1. **Walking skeleton approach validated**: RFA-7bh.1 established the full deployment foundation (42 resources validated), and RFA-7bh.2 extended it with admission security (60 total resources). No integration issues between stories.

2. **Offline validation pattern accepted**: Both stories used kustomize build + kubeconform for validation instead of requiring a live K8s cluster. PM accepted this precedent (consistent with EKS IaC stories in RFA-9fv epic), establishing that IaC has deterministic behavior.

3. **Zero rejections across both stories**: Comprehensive AC verification tables with manifest-level evidence enabled PM to accept without re-running tests.

4. **Resource budget discipline**: All services fit within 4 CPU / 8GB RAM (total: 450m CPU / 576Mi RAM for all pods), leaving ample headroom for Docker Desktop overhead.

## Learnings

### 1. Kustomize requires wrapper kustomization.yaml in each resource group (Important)
**Context:** RFA-7bh.1 needed to create kustomization.yaml wrappers in each resource group directory (spire/, spike/, observability/) for the local overlay to reference them. These are additive (don't modify existing manifests) but necessary for cross-directory references.
**Lesson:** When building Kustomize overlays that reference existing resource directories, plan for creating wrapper kustomization.yaml files. This is a one-time cost per resource group.

### 2. SPIRE agent requires privileged PSS on its namespace (Important)
**Context:** SPIRE agent DaemonSet uses hostPID: true and hostNetwork: true, which conflicts with "restricted" PodSecurity Standard. The local overlay relaxes spire-system to "privileged" PSS for dev. This is also an issue in the EKS base manifests.
**Lesson:** SPIRE agent inherently requires privileged access (hostPID for attestation, hostNetwork for node-level identity). Document this as a known security boundary and ensure PSS annotations match in all overlays.

### 3. Docker Desktop kubeadm does not support k8s_psat attestation (Important)
**Context:** Docker Desktop lacks an OIDC provider, so k8s_psat (Projected Service Account Token) attestation doesn't work. join_token is the correct alternative for local development SPIRE.
**Lesson:** For local K8s development with SPIRE, use join_token attestation. Reserve k8s_psat for managed K8s clusters (EKS, GKE) that have OIDC providers configured.

### 4. sigstore/policy-controller uses opt-in namespace labeling (Nice-to-have)
**Context:** RFA-7bh.2 used the policy.sigstore.dev/include=true label on namespaces for opt-in enforcement. This is more flexible than Gatekeeper's namespace exclusion approach because enforcement is at the namespace level.
**Lesson:** sigstore/policy-controller and OPA Gatekeeper use different namespace targeting strategies (opt-in vs opt-out). Both can coexist because K8s API server calls admission webhooks in parallel with no ordering dependency.

### 5. Kustomize strategic merge patches for StatefulSet VCTs require full block (Nice-to-have)
**Context:** RFA-7bh.1 discovered that Kustomize strategic merge patches for StatefulSet volumeClaimTemplates require specifying the full VCT block (not just the field to change) because VCTs are matched by metadata.name.
**Lesson:** When patching StatefulSet VCTs via Kustomize, include the complete volumeClaimTemplates entry, not just the fields being modified.

### 6. IaC validation via kustomize build + kubeconform is appropriate for K8s manifest stories (Important)
**Context:** Both stories were accepted using offline validation (kustomize build + kubeconform) without requiring a live cluster. This established a clear precedent consistent with EKS IaC stories.
**Lesson:** For K8s Infrastructure-as-Code stories, kustomize build + kubeconform is the appropriate validation tier. Manifest correctness is deterministic -- if ValidatingWebhookConfiguration says failurePolicy: Fail, unsigned images WILL be rejected. Reserve live cluster testing for E2E integration stories.

### 7. SPIRE registration Job has a design gap in EKS base manifests (Nice-to-have)
**Context:** RFA-7bh.1 observed that infra/eks/spire/registration-entries.yaml mounts an emptyDir for spire-server-socket but needs the actual server socket. The Job cannot work as written and would need gRPC API or kubectl exec.
**Lesson:** Registration entry Jobs that need SPIRE server socket access should either use the gRPC API service directly or be implemented as kubectl exec commands rather than standalone Jobs with socket mounts.

## Discovered Issues

- **RFA-3ja** (P2): SPIRE PSS conflict -- spire-system namespace needs privileged PSS annotation in EKS base
- **RFA-38s** (P3): SPIRE registration Job design gap -- Job mounts emptyDir instead of actual server socket
- **RFA-tv9** (P2): Production hardening -- policy-controller TLS secret auto-generation needed for non-local overlays

## Metrics

| Metric | Value |
|--------|-------|
| Stories | 2 |
| Rejections | 0 |
| K8s resources (local overlay) | 60 (42 base + 18 admission) |
| Kubeconform valid | 54 (6 CRDs skipped - expected) |
| Resource budget | 450m CPU / 576Mi RAM (of 4 CPU / 8GB) |
| Discovered issues | 3 (RFA-3ja, RFA-38s, RFA-tv9) |
