# Observability Stack -- EKS Deployment

**Story:** RFA-9fv.7

Full observability stack for the PRECINCT POC on EKS:
OTEL collector routing traces to Phoenix, structured audit logs to S3 with
Object Lock, and Phoenix for trace visualization.

Optional extension: OpenSearch + OpenSearch Dashboards + audit forwarder for
indexed audit forensics and compliance evidence operations (Apache-2 stack).

## Architecture

```
+------------------+      +-------------------+      +-----------------+
| MCP Security     | OTLP | OpenTelemetry     | OTLP | Phoenix         |
| Gateway          +----->| Collector         +----->| (Trace Viewer)  |
| (gateway ns)     | 4317 | (observability ns)| 4317 | (observability) |
+--------+---------+      +-------------------+      +--------+--------+
         |                                                     |
         | Audit Events                                   Port 6006
         v                                                     |
+------------------+                                    +------v--------+
| S3 Bucket        |                                    | Operator      |
| Object Lock      |                                    | Dashboard     |
| (COMPLIANCE 90d) |                                    +---------------+
+------------------+
```

### Data Flow

1. **Traces**: Gateway emits OTLP traces to OTEL Collector (port 4317/4318)
2. **Collector**: Batches and forwards traces to Phoenix (port 4317)
3. **Phoenix**: Stores and visualizes traces, provides operator dashboard
4. **Audit**: Gateway writes hash-chained audit events to S3 via IRSA

### Correlation

Every audit event contains `trace_id`, `session_id`, and `decision_id` enabling
end-to-end session reconstruction. The `trace_id` in audit events matches the
`trace_id` in Phoenix spans for cross-reference.

## Components

| Component | Location | Purpose |
|-----------|----------|---------|
| OTEL Collector | `otel-collector/` | Trace/metric/log pipeline |
| Phoenix | `phoenix/` | Trace visualization and dashboards |
| Audit S3 Sink | `audit/` | Immutable audit log storage |
| OpenSearch Extension (optional) | `opensearch/` | Indexed audit search + dashboards |
| NetworkPolicies | `observability-policies.yaml` | Traffic flow control |
| Namespace | `observability-namespace.yaml` | Isolation boundary |

## Prerequisites

- kubectl configured with EKS cluster context (from RFA-9fv.2)
- Gateway deployed (`make -C ../gateway deploy`)
- SPIRE deployed (`make -C ../spire deploy`)
- kubeconform installed (`brew install kubeconform`) for offline validation
- For audit S3: OpenTofu/Terraform installed
- For OpenSearch extension: required TLS and credential secrets created in `observability` namespace (see `opensearch/README.md`)

## Deployment

### Quick Start (all components except S3 IAM)

```bash
make deploy
```

### Step by Step

```bash
# 1. Deploy namespace and RBAC
make deploy-namespace
make deploy-rbac

# 2. Deploy ConfigMaps
make deploy-configs

# 3. Deploy Phoenix (must be ready before collector starts)
make deploy-phoenix

# 4. Deploy OTEL Collector
make deploy-otel

# 5. Apply NetworkPolicies
make deploy-policies

# 6. (Optional) Deploy audit S3 IAM resources
make deploy-audit

# 7. (Optional) Deploy OpenSearch extension
make deploy-opensearch
```

### Audit S3 Setup

The S3 bucket and IAM role are managed by OpenTofu:

```bash
cd audit

# Initialize
tofu init

# Review plan
tofu plan -var="oidc_provider_arn=<from-eks-output>" \
          -var="oidc_provider_url=<from-eks-output>"

# Apply
tofu apply -var="oidc_provider_arn=<from-eks-output>" \
           -var="oidc_provider_url=<from-eks-output>"

# Update IRSA annotation with the output role ARN
# Edit audit-s3-rbac.yaml and replace <ACCOUNT_ID> placeholder
```

## Verification

```bash
# Check all components
make verify

# Check specific component logs
make logs-otel
make logs-phoenix

# Validate manifests offline
make dry-run
make dry-run-opensearch
```

### Immutable Audit Sink Validation (K8s)

```bash
# Render full observability manifests (includes audit S3 config + RBAC)
kustomize build .

# Generate machine-readable immutable-sink proof artifact
bash ../../tests/e2e/validate_immutable_audit_sink.sh
```

Proof artifact path:

- `tests/e2e/artifacts/immutable-audit-sink-proof.json`

## Phoenix Dashboard Access

Phoenix UI is exposed via NodePort:

```bash
# Get the assigned NodePort
kubectl -n observability get svc phoenix \
  -o jsonpath='{.spec.ports[?(@.name=="http-ui")].nodePort}'

# Access via: http://<node-ip>:<nodePort>

# For port-forward (alternative):
kubectl -n observability port-forward svc/phoenix 6006:6006
# Access via: http://localhost:6006
```

### Dashboard Views

Phoenix provides operator visibility into:

- **Top blocked tools/destinations** -- which tools are being denied most
- **Step-up gating rate and reason codes** -- when and why step-up is triggered
- **Deep scan backlog and false-positive rates** -- scan queue health
- **Tool hash mismatch events** -- potential rug-pull detection
- **"Sensitive read -> external send" near-misses** -- DLP near-miss patterns

These views are constructed from the OTEL traces emitted by the gateway's
13-middleware chain, correlated via `trace_id`.

### OpenSearch Dashboards Access (Optional)

OpenSearch Dashboards is exposed as a ClusterIP service:

```bash
kubectl -n observability port-forward svc/opensearch-dashboards 5601:5601
# Access via: https://localhost:5601
```

OpenSearch API:

```bash
kubectl -n observability port-forward svc/opensearch 9200:9200
# Access via: https://localhost:9200
```

## Audit Event Schema

Every audit event written to S3 follows this schema (Reference Architecture
Section 10.4):

```json
{
  "timestamp": "2026-02-04T14:30:15.123456Z",
  "event_type": "tool.invocation",
  "session_id": "sess-abc123",
  "decision_id": "d7a8f3b2-...",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "spiffe_id": "spiffe://acme.corp/agents/mcp-client/...",
  "action": "mcp_request",
  "result": "completed",
  "method": "POST",
  "path": "/mcp",
  "status_code": 200,
  "security": {
    "tool_hash_verified": true,
    "safezone_flags": []
  },
  "authorization": {
    "opa_decision_id": "d7a8f3b2-1234-5678-9abc-def012345678",
    "allowed": true
  },
  "prev_hash": "<sha256-of-previous-event>",
  "bundle_digest": "<sha256-of-opa-policy-bundle>",
  "registry_digest": "<sha256-of-tool-registry>"
}
```

### S3 Object Lock

- **Mode:** COMPLIANCE (no one can delete within retention period)
- **Retention:** 90 days minimum
- **Hash chain:** `prev_hash` field enables tamper detection
- **Legal hold:** Supported via IAM policy permissions

## Cleanup

```bash
# Remove Kubernetes resources
make undeploy

# Remove S3 bucket and IAM resources (separate)
cd audit && tofu destroy
```

## NetworkPolicy Summary

| Source | Destination | Ports | Purpose |
|--------|-------------|-------|---------|
| gateway | otel-collector | 4317, 4318 | OTLP trace export |
| otel-collector | phoenix | 4317 | Trace forwarding |
| any | phoenix | 6006 | UI access |
| otel-collector | kube-dns | 53 | DNS resolution |
| phoenix | kube-dns | 53 | DNS resolution |
| opensearch-dashboards | opensearch | 9200 | HTTPS API + mTLS |
| opensearch-audit-forwarder | opensearch | 9200 | Audit ingest + mTLS |
| any | opensearch-dashboards | 5601 | Dashboards UI (restrict in production) |
