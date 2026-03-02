# OpenSearch Observability Profile (Optional)

This profile complements Phoenix tracing with searchable audit evidence in an
Apache-2 licensed stack:

- OpenSearch
- OpenSearch Dashboards
- Fluent Bit (audit JSONL forwarder)

Use this when you need security operations workflows such as:

- long-lived audit search and filtering
- analyst dashboards for deny/allow trends
- investigation by `decision_id`, `trace_id`, `spiffe_id`, or signal keys
- compliance evidence workflows that benefit from indexed lookup

## Why This Is Complementary (Not a Replacement)

- Phoenix remains the best local trace-waterfall view for middleware latency and
  LLM inference path debugging.
- OpenSearch is the better tool for indexed security evidence, compliance
  operations, and incident response pivots.
- OTel remains the vendor-neutral telemetry transport abstraction.

## Start / Stop

```bash
# Start core stack as usual (auto-starts Phoenix network if needed)
make up

# Enable OpenSearch profile
make opensearch-up

# Seed index template + dashboard objects
make opensearch-seed

# Validate health/template wiring
make opensearch-validate

# Stop profile (data preserved)
make opensearch-down

# Stop and wipe all OpenSearch profile data
make opensearch-reset
```

Dashboards UI: `http://localhost:5601`

OpenSearch API: `http://localhost:9200`

## Kubernetes (Local Overlay + EKS Manifests)

Optional Kubernetes extension:

- manifests: `infra/eks/observability/opensearch/`
- local overlay: `infra/eks/overlays/local-opensearch/`

Commands:

```bash
# Full local K8s stack + OpenSearch extension
make k8s-opensearch-up

# Validate manifests only
make -C infra/eks/observability dry-run-opensearch
```

Secrets required before deploy (namespace `observability`):

- `opensearch-node-tls` (`tls.crt`, `tls.key`, `ca.crt`)
- `opensearch-client-tls` (`tls.crt`, `tls.key`, `ca.crt`)
- `opensearch-dashboards-server-tls` (`tls.crt`, `tls.key`)
- `opensearch-admin-credentials` (`username`, `password`)

All OpenSearch extension auth and certificate material is loaded from Secrets;
no inline credentials are stored in manifests.

## Data Flow

1. Gateway writes structured audit JSONL to `/var/log/gateway/audit.jsonl` (profile override only).
2. Fluent Bit tails that file from shared volume `gateway-audit-logs`.
3. Fluent Bit indexes records into `precinct-audit-*`.
4. Dashboards consumes the indexed data for analyst exploration.

## Example Investigator Queries (KQL)

- `decision_id:* and result:denied`
- `spiffe_id:"spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"`
- `middleware:"dlp_scan" and security.signal_keys:*`
- `status_code:403 and path:"/rpc"`

## Compliance-Oriented Query Patterns

- Prove policy enforcement events for a date window:
  - filter `middleware:"opa_policy"` and aggregate by `result`.
- Prove DLP controls are active:
  - filter `middleware:"dlp_scan"` and check signal keys over time.
- Cross-link investigations:
  - pivot from `decision_id` in evidence reports to indexed record, then to
    `trace_id` in Phoenix.

`agw` can export compliance evidence from OpenSearch:

```bash
export AGW_OPENSEARCH_PASSWORD='<secret>'
go run ./cmd/agw compliance collect \
  --framework soc2 \
  --audit-source opensearch \
  --opensearch-url https://opensearch.observability.svc.cluster.local:9200 \
  --opensearch-ca-cert /certs/ca.crt \
  --opensearch-client-cert /certs/client.crt \
  --opensearch-client-key /certs/client.key
```

## Notes

- This profile is optional and intentionally non-blocking for local workflows.
- For immutable audit requirements, continue using the immutable sink guidance in
  `docs/compliance/immutable-audit-evidence-path.md`.
