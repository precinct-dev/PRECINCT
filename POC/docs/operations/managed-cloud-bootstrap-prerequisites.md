# Managed Cloud Bootstrap Prerequisites

## Purpose

Define the minimum managed-cloud inputs required to execute staging bootstrap and runtime validation safely and reproducibly.

This document is the prerequisite contract for `RFA-l6h6.8.9` and its downstream runtime campaign dependency (`RFA-l6h6.8.5`).

## Required Inputs

| Input | Description | Owner |
|---|---|---|
| `MANAGED_K8S_PROVIDER` | Managed Kubernetes provider (`digitalocean`, `eks`, `gke`, etc.) | Platform |
| `MANAGED_K8S_CONTEXT` | Reachable kubeconfig context for staging cluster | Platform |
| `MANAGED_K8S_REQUIRED_NAMESPACES` | Comma-separated namespace list expected before rollout | Platform + SRE |
| Cluster metadata | cluster name, region, version, nodepool baseline | Platform |
| Access material | kubeconfig/auth flow and rotation owner | Platform Security |

## Ownership Matrix

| Responsibility | Primary Owner | Backup Owner |
|---|---|---|
| Cluster provisioning and lifecycle | Platform | SRE |
| Credential bootstrap and rotation | Platform Security | Platform |
| Namespace baseline and rollout wiring | SRE | Platform |
| Runtime campaign execution (`RFA-l6h6.8.5`) | Security Engineering | SRE |

## Deterministic Preflight

Run the managed-cloud prerequisite preflight:

```bash
bash scripts/operations/managed_cloud_bootstrap_preflight.sh
```

Expected behavior:

- Fail fast with actionable guidance if required environment variables are missing.
- Fail fast if the managed context is unreachable.
- Fail fast if required namespaces are missing.
- Pass only when all prerequisites are satisfied.

## Handoff Artifact Template

Use this template to hand off bootstrap/access recovery requirements to platform teams:

- `docs/operations/artifacts/managed-cloud-bootstrap-handoff.template.json`

## Consumption by Runtime Campaign

`RFA-l6h6.8.5` must reference this contract and capture the preflight output before running managed runtime control validation.
