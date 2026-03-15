# OpenSearch Observability Extension (EKS)

Optional extension for `deploy/terraform/observability` that adds:

- OpenSearch (TLS + mTLS)
- OpenSearch Dashboards (HTTPS UI + mTLS client cert)
- Audit forwarder (Fluent Bit) that tails gateway pod logs and writes audit events to OpenSearch

## Security Contract

- Secrets: all credentials and certs are referenced via Kubernetes `Secret` (no literal values in repo)
- mTLS: OpenSearch HTTP API is TLS-enabled and requires client certs
- Identity: workloads run under dedicated service accounts and are intended to be SPIRE-registered

## Required Secrets

Create these in namespace `observability` before deploying:

- `opensearch-node-tls` with keys `tls.crt`, `tls.key`, `ca.crt`
- `opensearch-client-tls` with keys `tls.crt`, `tls.key`, `ca.crt`
- `opensearch-dashboards-server-tls` with keys `tls.crt`, `tls.key`
- `opensearch-admin-credentials` with keys `username`, `password`

Example (placeholder values):

```bash
kubectl -n observability create secret generic opensearch-admin-credentials \
  --from-literal=username=admin \
  --from-literal=password='<replace-me>'
```

## Deploy

```bash
# Base observability + OpenSearch extension
kustomize build deploy/terraform/overlays/local-opensearch | kubectl apply -f -
```

## Verify

```bash
kubectl -n observability get pods -l app.kubernetes.io/name=opensearch
kubectl -n observability get pods -l app.kubernetes.io/name=opensearch-dashboards
kubectl -n observability get pods -l app.kubernetes.io/name=opensearch-audit-forwarder
kubectl -n observability get svc opensearch opensearch-dashboards
```
