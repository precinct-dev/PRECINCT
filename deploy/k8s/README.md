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

## ConfigMap Population

The base kustomization creates a `gateway-config` ConfigMap with only a
`_placeholder` key (to pass kubeconform validation). **The gateway pod will not
start until this ConfigMap is populated with the actual configuration files.**

### What happens if not populated

The gateway deployment mounts specific keys from `gateway-config` with
`optional: false`. If any key is missing, the kubelet cannot mount the volume
and the pod stays in `ContainerCreating` or enters `CrashLoopBackOff`. You
will see events like:

```
Warning  FailedMount  configmap "gateway-config" has no key "mcp_policy.rego"
```

### Required ConfigMap keys

The deployment manifest (`base/gateway/gateway-deployment.yaml`) expects these
keys in the `gateway-config` ConfigMap:

**OPA policies** (mounted at `/config/opa/`):

| Key | Source file |
|-----|------------|
| `mcp_policy.rego` | `config/opa/mcp_policy.rego` |
| `ui_policy.rego` | `config/opa/ui_policy.rego` |
| `ui_csp_policy.rego` | `config/opa/ui_csp_policy.rego` |
| `exfiltration.rego` | `config/opa/exfiltration.rego` |
| `context_policy.rego` | `config/opa/context_policy.rego` |
| `principal_policy.rego` | `config/opa/principal_policy.rego` |
| `tool_grants.yaml` | `config/opa/tool_grants.yaml` |
| `ui_capability_grants.yaml` | `config/opa/ui_capability_grants.yaml` |

**Registry and attestation artifacts** (mounted individually at `/config/`):

| Key | Source file |
|-----|------------|
| `tool-registry.yaml` | `config/tool-registry.yaml` |
| `tool-registry.yaml.sig` | `config/tool-registry.yaml.sig` |
| `capability-registry-v2.yaml` | `config/capability-registry-v2.yaml` |
| `model-provider-catalog.v2.yaml` | `config/model-provider-catalog.v2.yaml` |
| `model-provider-catalog.v2.yaml.sig` | `config/model-provider-catalog.v2.yaml.sig` |
| `attestation-ed25519.pub` | `config/attestation-ed25519.pub` |
| `guard-artifact.bin` | `config/guard-artifact.bin` |
| `guard-artifact.bin.sig` | `config/guard-artifact.bin.sig` |
| `risk_thresholds.yaml` | `config/risk_thresholds.yaml` |

### How to populate

**Option 1 -- kubectl (one-liner):**

```bash
kubectl create configmap gateway-config \
  --from-file=config/opa/ \
  --from-file=tool-registry.yaml=config/tool-registry.yaml \
  --from-file=tool-registry.yaml.sig=config/tool-registry.yaml.sig \
  --from-file=capability-registry-v2.yaml=config/capability-registry-v2.yaml \
  --from-file=model-provider-catalog.v2.yaml=config/model-provider-catalog.v2.yaml \
  --from-file=model-provider-catalog.v2.yaml.sig=config/model-provider-catalog.v2.yaml.sig \
  --from-file=attestation-ed25519.pub=config/attestation-ed25519.pub \
  --from-file=guard-artifact.bin=config/guard-artifact.bin \
  --from-file=guard-artifact.bin.sig=config/guard-artifact.bin.sig \
  --from-file=risk_thresholds.yaml=config/risk_thresholds.yaml \
  -n gateway --dry-run=client -o yaml | kubectl apply -f -
```

**Option 2 -- Makefile:**

```bash
make k8s-sync-config
```

This copies the canonical `config/` files into the Kustomize overlay directory
so that `configMapGenerator` picks them up on the next `kubectl apply -k`.

### When to re-populate

Re-run the command above (or `make k8s-sync-config` followed by
`kubectl apply -k`) whenever you change OPA policies, the tool registry, or
any other config file. The gateway reads these files at startup; a rolling
restart (`kubectl rollout restart deployment/mcp-security-gateway -n gateway`)
picks up the new ConfigMap contents.

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
