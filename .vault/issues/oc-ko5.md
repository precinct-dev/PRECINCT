---
id: oc-ko5
title: "GAP-7: Ensure generic Kubernetes deployment readiness (cloud-agnostic)"
status: closed
priority: 3
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:24:24Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:12a0ded093fdc91cb1a910ab8ec860bb7e67fd2ca6a2bd933e4e32dc0ef14aca"
closed_at: 2026-02-21T10:25:33Z
close_reason: "Cloud-agnostic k8s manifests created under infra/k8s/. 29 resources validated (kubeconform strict + kubectl dry-run). EKS preserved as optional overlay. No AWS hard dependencies in base manifests."
---

## Description
WHAT: Ensure the existing Kubernetes deployment manifests in infra/ are cloud-agnostic and can target any conformant Kubernetes cluster (EKS, GKE, AKS, kind, k3s, etc.). Remove any AWS/EKS-specific assumptions. Prepare generic Terraform or Kustomize configuration that can be applied when a cluster is available.

UPDATED CONSTRAINT: No AWS account is currently available for testing. All infrastructure code must be generic Kubernetes -- no EKS-specific resources (IRSA, EKS add-ons, aws-node DaemonSet assumptions). The actual deployment will happen later when a cluster environment is available. For now, validate that manifests are syntactically correct and cloud-agnostic.

WHY: The original story assumed EKS deployment. Since no cloud account is available yet, the infrastructure code should be portable so it can target whatever cluster becomes available first (could be EKS, GKE, or even a local kind cluster for CI).

HOW:
1. Review infra/eks/ and identify EKS-specific resources
2. Refactor to infra/k8s/ with generic Kubernetes manifests (Deployments, Services, ConfigMaps, etc.)
3. Keep the EKS Terraform as an optional overlay but ensure the core k8s manifests work on any cluster
4. Validate manifests with kubectl --dry-run=client or similar offline validation
5. If Helm charts exist, ensure they have no hard EKS dependencies

ACCEPTANCE CRITERIA:
AC1: Core k8s manifests (Deployment, Service, ConfigMap) exist and pass kubectl --dry-run=client validation
AC2: No hard dependencies on AWS-specific APIs or EKS-specific features in the core manifests
AC3: EKS-specific Terraform preserved as optional overlay, not required for basic deployment
AC4: Documentation updated noting which cluster types are supported
AC5: Actual deployment deferred -- no cloud resources created in this story

## Acceptance Criteria
AC1: infra/eks/versions.tf contains S3 backend configuration with state locking
AC2: EKS cluster is deployed and reachable (kubectl get nodes shows Ready nodes)
AC3: Gateway pods are running in the cluster (kubectl get pods shows Running)
AC4: Deployment evidence captured in docs/evidence/ (node list, pod list, terraform outputs)
AC5: terraform state is stored in S3 (not local)

## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links


## Comments
