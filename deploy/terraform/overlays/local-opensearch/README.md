# Local OpenSearch Overlay

This overlay composes:

- `../local` (full local EKS-compatible stack)
- `../../observability/opensearch` (optional OpenSearch extension)

Build:

```bash
kustomize build infra/eks/overlays/local-opensearch
```

Apply:

```bash
kubectl apply -k infra/eks/overlays/local-opensearch
```
