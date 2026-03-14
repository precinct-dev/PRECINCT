# Cloud-Agnostic Kubernetes Manifests

Generic Kubernetes manifests for the PRECINCT POC. These
manifests work on **any conformant Kubernetes cluster**: EKS, GKE, AKS, kind,
k3s, minikube, Docker Desktop Kubernetes, etc.

Story: oc-ko5 (GAP-7)

## Directory Structure

```
deploy/k8s/
  base/                          # Cloud-agnostic base manifests
    gateway/                     # PRECINCT Gateway
      gateway-namespace.yaml
      gateway-rbac.yaml
      gateway-configmap.yaml
      gateway-deployment.yaml
      gateway-service.yaml
      kustomization.yaml
    mcp-server/                  # Placeholder MCP tool server
      mcp-server-namespace.yaml
      mcp-server-rbac.yaml
      mcp-server-deployment.yaml
      mcp-server-service.yaml
      kustomization.yaml
    policies/                    # NetworkPolicies (default-deny + allow rules)
      default-deny.yaml
      gateway-allow.yaml
      mcp-server-allow.yaml
      kustomization.yaml
    observability/               # OTEL Collector + Phoenix
      observability-namespace.yaml
      observability-policies.yaml
      otel-collector/
      phoenix/
      kustomization.yaml
    kustomization.yaml           # Top-level base
  overlays/
    dev/                         # Dev overlay (debug logging, low resources)
    local/                       # Local cluster overlay (kind, k3s, etc.)
```

## Quick Start

### 1. Validate manifests offline (no cluster required)

```bash
# Kustomize build (dry-run)
kustomize build deploy/k8s/base

# kubeconform validation
kustomize build deploy/k8s/base | kubeconform -summary -strict

# kubectl dry-run
kustomize build deploy/k8s/base | kubectl apply --dry-run=client -f -
```

### 2. Deploy to any cluster

```bash
# Apply base manifests
kubectl apply -k deploy/k8s/base

# Or with dev overlay
kubectl apply -k deploy/k8s/overlays/dev

# Or with local overlay (kind, Docker Desktop)
kubectl apply -k deploy/k8s/overlays/local
```

### 3. Verify deployment

```bash
kubectl get namespaces
kubectl -n gateway get pods
kubectl -n tools get pods
kubectl -n observability get pods
```

## Cloud-Specific Extensions

The base manifests contain NO cloud-specific resources. Cloud-specific features
should be added via Kustomize overlays:

| Feature | AWS/EKS | GKE | AKS | Local |
|---------|---------|-----|-----|-------|
| Container registry | ECR | GCR/AR | ACR | local/ghcr.io |
| IAM for pods | IRSA annotation | Workload Identity | Pod Identity | N/A |
| LoadBalancer | ALB Controller | GKE LB | Azure LB | NodePort |
| Storage class | gp3 | pd-standard | managed-premium | hostpath |
| Audit sink | S3 | GCS | Blob Storage | file/stdout |

For AWS/EKS-specific resources (Terraform, IRSA, VPC, S3 audit), see
`deploy/terraform/` which is preserved as an optional EKS overlay.

## Relationship to deploy/terraform/

The `deploy/terraform/` directory is preserved intact as an **optional EKS-specific
overlay**. It contains:

- EKS cluster Terraform (`main.tf`, `variables.tf`, etc.)
- AWS-specific Kustomize overlays with IRSA annotations
- S3 MCP server (AWS S3 tool -- inherently cloud-specific)
- S3 audit sink configuration
- EKS-specific admission control setup

The core Kubernetes YAML in `deploy/terraform/` (gateway, mcp-server, policies,
observability, spire) is functionally equivalent to the manifests here in
`deploy/k8s/base/`. The `deploy/k8s/` tree is the canonical cloud-agnostic
source; `deploy/terraform/` adds AWS-specific layering on top.

## Supported Cluster Types

| Cluster Type | Status | Notes |
|-------------|--------|-------|
| kind | Validated | Use `deploy/k8s/cluster.yaml` for cluster config |
| Docker Desktop K8s | Validated | Enable in Docker Desktop settings |
| k3s | Ready | Standard k8s API; should work out of the box |
| minikube | Ready | Standard k8s API; should work out of the box |
| AWS EKS | Ready | Add IRSA/VPC via `deploy/terraform/` overlay |
| Google GKE | Ready | Add Workload Identity via GKE overlay |
| Azure AKS | Ready | Add Pod Identity via AKS overlay |

## Prerequisites

- `kubectl` >= 1.28
- `kustomize` >= 5.0 (or use `kubectl -k`)
- A conformant Kubernetes cluster (for actual deployment)
- A NetworkPolicy-capable CNI for network policy enforcement (Calico, Cilium,
  etc. -- most managed clusters include one by default)
