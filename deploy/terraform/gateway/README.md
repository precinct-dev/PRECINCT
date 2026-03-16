# PRECINCT Gateway - EKS Deployment

Story: RFA-9fv.4

## Architecture

The PRECINCT Gateway is the security enforcement point for all MCP JSON-RPC
requests. It runs a 13-middleware chain (authentication, authorization, DLP,
audit, etc.) before proxying requests to tool servers.

```
                    +-------------------+
                    |     Agents /      |
                    |    MCP Clients    |
                    +--------+----------+
                             |
                             | port 9090
                             v
                  +----------+----------+
   gateway ns --> | PRECINCT Gateway|
                  | (13-middleware chain)|
                  +----------+----------+
                             |
                             | port 8081 (NetworkPolicy enforced)
                             v
                  +----------+----------+
   tools ns ----> |   MCP Tool Server   |
                  |  (Docker MCP / mock)|
                  +---------------------+
```

### Namespaces

| Namespace | Purpose | SPIFFE ID |
|-----------|---------|-----------|
| `gateway` | PRECINCT Gateway | `spiffe://precinct.poc/ns/gateway/sa/precinct-gateway` |
| `tools`   | MCP tool servers | `spiffe://precinct.poc/ns/tools/sa/mcp-tool` |

### NetworkPolicy Enforcement

Default-deny is applied to both namespaces. Explicit allow rules permit:

- **Gateway ingress**: Any source on port 9090
- **Gateway egress**: tools:8081, spike-system:8443, kube-dns:53
- **Tools ingress**: Only from gateway namespace on port 8081
- **Tools egress**: kube-dns:53, internal CIDRs only (no public internet)

## Prerequisites

1. EKS cluster provisioned (RFA-9fv.2)
2. SPIRE deployed (`make -C ../spire deploy`)
3. SPIKE deployed (`make -C ../spike deploy`)
4. NetworkPolicy-capable CNI installed (Calico or Cilium)
5. Gateway container image built and available:
   ```bash
   # Build locally
   docker build -t precinct-gateway:latest -f deploy/compose/Dockerfile.gateway .

   # Push to ECR (production)
   aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
   docker tag precinct-gateway:latest <account>.dkr.ecr.<region>.amazonaws.com/precinct-gateway:latest
   docker push <account>.dkr.ecr.<region>.amazonaws.com/precinct-gateway:latest
   ```
6. `kubeconform` installed for offline validation (`brew install kubeconform`)

## Deployment Order

Deploy components in this order (dependencies flow top to bottom):

```bash
# 1. SPIRE (identity infrastructure)
make -C ../spire deploy

# 2. SPIKE (token service)
make -C ../spike deploy

# 3. MCP Tool Server (upstream target)
make -C ../mcp-server deploy

# 4. PRECINCT Gateway
make -C ../gateway deploy

# 5. NetworkPolicies (enforce after services are running)
make -C ../policies deploy
```

## Quick Reference

```bash
# Deploy everything
make deploy

# Check health
make verify

# View logs
make logs

# Validate manifests offline
make dry-run

# Remove everything
make undeploy
```

## Manifest Files

| File | Resource | Description |
|------|----------|-------------|
| `gateway-namespace.yaml` | Namespace | `gateway` namespace with pod security standards |
| `gateway-rbac.yaml` | ServiceAccount | Identity for SPIFFE attestation |
| `gateway-configmap.yaml` | ConfigMap (template) | Placeholder; real data populated by Makefile |
| `gateway-deployment.yaml` | Deployment | Gateway pod with env vars, volumes, probes |
| `gateway-service.yaml` | Service | ClusterIP on port 9090 |

## Configuration

The gateway reads its configuration from environment variables and mounted files:

| Variable | Value | Source |
|----------|-------|--------|
| `PORT` | 9090 | Deployment env |
| `UPSTREAM_URL` | `http://mcp-server.tools.svc.cluster.local:8081/mcp` | Base deployment env (staging/prod overlays override to strict `https://...`) |
| `OPA_POLICY_DIR` | `/config/opa` | ConfigMap mount |
| `TOOL_REGISTRY_CONFIG_PATH` | `/config/tool-registry.yaml` | ConfigMap mount |
| `MAX_REQUEST_SIZE_BYTES` | 10485760 (10 MB) | Deployment env |
| `SPIFFE_MODE` | `prod` | Deployment env |
| `SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | hostPath mount |
| `AUDIT_LOG_PATH` | `/tmp/audit.jsonl` | emptyDir mount |
| `LOG_LEVEL` | `info` | Deployment env |

Strict overlay notes:

- `deploy/terraform/overlays/staging` and `deploy/terraform/overlays/prod` set `ENFORCEMENT_PROFILE=prod_standard`.
- Strict overlays pin `MCP_TRANSPORT_MODE=mcp`, `SPIFFE_MODE=prod`, and `UPSTREAM_URL=https://...`.
- Strict overlays use Kustomize `digest:` image pins; `.github/workflows/promote.yaml` is the supported path for rewriting those digests during `dev -> staging -> prod` promotion.
- Run `make k8s-overlay-digest-validate OVERLAYS="staging prod"` before applying strict overlays to confirm the rendered gateway/tools manifests still satisfy the rendered `RequireImageDigest` Gatekeeper policy.
- `APPROVAL_SIGNING_KEY` is wired via `gateway-runtime-secrets` (`approval_signing_key` key), but the secret is expected to be provisioned out-of-band (external secret manager/cluster secret bootstrap). Staging/prod overlays intentionally do not ship literal signing-key defaults in-repo.

## Updating OPA Policies

When OPA policies change in `config/opa/`, redeploy the ConfigMap:

```bash
make deploy-configmap
# Then restart the gateway to pick up changes:
kubectl -n gateway rollout restart deployment/precinct-gateway
```

## Troubleshooting

### Gateway pod not starting
- Check SPIRE agent is running: `kubectl -n spire-system get pods`
- Check ConfigMap exists: `kubectl -n gateway get configmap gateway-config`
- Check events: `kubectl -n gateway describe pod -l app.kubernetes.io/name=precinct-gateway`

### Gateway cannot reach tool server
- Verify NetworkPolicies: `make -C ../policies verify`
- Check tools namespace: `kubectl -n tools get pods`
- Test connectivity: `kubectl -n gateway exec <pod> -- wget -q -O- http://mcp-server.tools.svc.cluster.local:8081/health`

### SPIFFE identity issues
- Check SPIRE entries: `make -C ../spire verify`
- Check agent socket exists on node: `ls /run/spire/sockets/`
