# SPIRE Deployment on EKS -- PRECINCT POC

Kubernetes manifests for deploying SPIRE Server (HA) and Agent (DaemonSet) on the EKS cluster provisioned by RFA-9fv.2.

Story: RFA-9fv.3

## Prerequisites

1. **EKS Cluster** provisioned and accessible (`kubectl get nodes` works)
2. **kubectl** configured for the target cluster
3. **SPIRE Agent socket path**: `/run/spire/sockets/agent.sock` (exposed via hostPath)

## Architecture

```
+-------------------+     +-------------------+
| SPIRE Server (0)  |     | SPIRE Server (1)  |   StatefulSet (2 replicas)
| SQLite + Keys     |     | SQLite + Keys     |   Each has its own PVC
+--------+----------+     +--------+----------+
         |                         |
         +--- spire-server-api ----+  (ClusterIP Service, port 8081)
                    |
    +---------------+---------------+
    |               |               |
+---v---+      +---v---+      +---v---+
| Agent |      | Agent |      | Agent |   DaemonSet (one per node)
| Node1 |      | Node2 |      | Node3 |
+---+---+      +---+---+      +---+---+
    |               |               |
    v               v               v
  /run/spire/sockets/agent.sock     (hostPath, workloads mount this)
```

## SPIFFE ID Scheme

| Workload | SPIFFE ID | Selectors |
|----------|-----------|-----------|
| SPIRE Agent (node) | `spiffe://precinct.poc/agent/k8s-psat` | `k8s_psat:cluster:precinct-poc` |
| PRECINCT Gateway | `spiffe://precinct.poc/ns/gateway/sa/mcp-security-gateway` | `k8s:ns:gateway`, `k8s:sa:mcp-security-gateway` |
| MCP Tool Servers | `spiffe://precinct.poc/ns/tools/sa/mcp-tool` | `k8s:ns:tools`, `k8s:sa:mcp-tool` |
| SPIKE Nexus | `spiffe://precinct.poc/ns/spike-system/sa/spike-nexus` | `k8s:ns:spike-system`, `k8s:sa:spike-nexus` |
| OpenSearch | `spiffe://precinct.poc/ns/observability/sa/opensearch` | `k8s:ns:observability`, `k8s:sa:opensearch` |
| OpenSearch Dashboards | `spiffe://precinct.poc/ns/observability/sa/opensearch-dashboards` | `k8s:ns:observability`, `k8s:sa:opensearch-dashboards` |
| OpenSearch Audit Forwarder | `spiffe://precinct.poc/ns/observability/sa/opensearch-audit-forwarder` | `k8s:ns:observability`, `k8s:sa:opensearch-audit-forwarder` |

## Deployment

```bash
cd deploy/terraform/spire

# Deploy all SPIRE components
make deploy

# Or deploy step-by-step:
make deploy-server   # 1. Server (StatefulSet + Services)
make deploy-agent    # 2. Agent (DaemonSet)
make deploy-entries  # 3. Registration entries (via kubectl exec)
```

## Verification

```bash
# Check health of all components
make verify

# Detailed pod status
make status

# Tail logs
make logs-server
make logs-agent
```

## Validation (Without a Cluster)

```bash
# Validate YAML syntax and Kubernetes API compatibility
make dry-run
```

## Teardown

```bash
make undeploy
```

## Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | `spire-system` namespace with pod security labels |
| `server-configmap.yaml` | SPIRE Server configuration (k8s_psat, SQLite, k8sbundle) |
| `server-rbac.yaml` | ServiceAccount, ClusterRole, RoleBindings for server |
| `server-statefulset.yaml` | HA StatefulSet (2 replicas) with PVC |
| `server-service.yaml` | Headless + ClusterIP services for gRPC API |
| `agent-configmap.yaml` | SPIRE Agent configuration (k8s_psat, k8s attestor) |
| `agent-rbac.yaml` | ServiceAccount, ClusterRole for agent |
| `agent-daemonset.yaml` | DaemonSet with hostPath socket + projected token |
| `bundle-configmap.yaml` | Trust bundle placeholder (auto-populated by server) |
| `registration-entries.yaml` | ConfigMap with registration script (kubectl exec approach) |
| `Makefile` | Deployment, verification, and cleanup targets |

## Key Design Decisions

1. **Raw manifests over Helm**: Simpler for the POC, full visibility into every resource, no Helm dependency.
2. **k8s_psat attestation**: Uses EKS OIDC provider for cryptographic node attestation (more secure than join_token).
3. **SQLite per replica**: Acceptable for POC. Production should use PostgreSQL for true HA consensus.
4. **hostPath for agent socket**: Standard SPIRE pattern. Workload pods mount `/run/spire/sockets/` to access the Workload API.
5. **k8sbundle notifier**: Automatically distributes trust bundle to agents via ConfigMap.
6. **kubectl exec for registration (RFA-38s)**: The SPIRE server CLI only supports Unix socket communication (`-socketPath`), not TCP/gRPC addresses. A standalone Kubernetes Job cannot share the server pod's socket filesystem. Therefore, registration entries are created via `kubectl exec` into the server pod. Production deployments should use [spire-controller-manager](https://github.com/spiffe/spire-controller-manager) for CRD-based automatic registration.

## Migrating Workloads from Docker Compose

| Docker Compose | EKS |
|---------------|-----|
| `join_token` NodeAttestor | `k8s_psat` NodeAttestor |
| `docker` WorkloadAttestor | `k8s` WorkloadAttestor |
| `poc.local` trust domain | `precinct.poc` trust domain |
| Volume-shared sockets | hostPath-shared sockets |
| `insecure_bootstrap = true` | Trust bundle via ConfigMap |

## Next Steps

- **RFA-9fv.4**: Deploy gateway + MCP servers, mounting SPIRE agent socket for SVID acquisition
- **Production**: Replace SQLite with PostgreSQL, add mTLS between server replicas
