# Sidecar Identity: Deploying Third-Party Tools with SPIFFE

This guide explains how to deploy third-party tools (mcp2cli, DSPy agents, LangGraph
orchestrators, or any MCP client) inside PRECINCT with automatic SPIFFE identity,
without modifying the tools themselves.

## Architecture

```
+-------------------+     +------------------+     +-------------------+
| Third-party tool  | --> | Envoy sidecar    | --> | PRECINCT Gateway  |
| (mcp2cli, DSPy,   |     | 127.0.0.1:9090   |     | precinct-gateway  |
|  LangGraph, etc.) |     | +X-SPIFFE-ID hdr |     | :9090 (Compose)   |
+-------------------+     +------------------+     | :9090 (K8s)       |
                                                    +-------------------+
```

The Envoy sidecar:
1. Listens on `127.0.0.1:9090` in the same network namespace as the tool
2. Injects the `X-SPIFFE-ID` header with the tool's registered SPIFFE identity
3. Forwards all requests to the PRECINCT Gateway
4. The gateway authenticates and authorizes the request using the SPIFFE ID

## Quick Start (Docker Compose)

### 1. Register the tool with SPIRE

Generate the registration command for your tool:

```bash
./deploy/sidecar/spire-registration-template.sh \
    --tool-name mcp2cli \
    --env dev \
    --mode compose
```

Add the output to `scripts/register-spire-entries.sh` using the `reg()` helper:

```bash
reg "spiffe://poc.local/agents/mcp-client/mcp2cli/dev" \
    -selector docker:label:spiffe-id:mcp2cli
```

### 2. Deploy with the sidecar overlay

```bash
# Start the main PRECINCT stack
make demo-compose

# Add the sidecar example overlay
docker compose \
    -f deploy/compose/docker-compose.yml \
    -f deploy/sidecar/docker-compose.sidecar-example.yml \
    up -d
```

### 3. Configure your tool

Point your tool at `http://127.0.0.1:9090` as the gateway endpoint. The sidecar
handles identity injection transparently.

Environment variables for the sidecar overlay:

| Variable | Default | Description |
|----------|---------|-------------|
| `SIDECAR_SPIFFE_ID` | `spiffe://poc.local/agents/mcp-client/sidecar-client/dev` | SPIFFE ID injected into requests |
| `SIDECAR_TOOL_NAME` | `sidecar-client` | Docker label for SPIRE attestation |

Example with custom identity:

```bash
SIDECAR_SPIFFE_ID=spiffe://poc.local/agents/mcp-client/mcp2cli/dev \
SIDECAR_TOOL_NAME=mcp2cli \
docker compose \
    -f deploy/compose/docker-compose.yml \
    -f deploy/sidecar/docker-compose.sidecar-example.yml \
    up -d
```

### 4. Test the connection

```bash
docker exec sidecar-client sh -c \
    'curl -s http://127.0.0.1:9090/health'
```

## Quick Start (Kubernetes)

### 1. Register the tool with SPIRE

Generate the K8s registration command:

```bash
./deploy/sidecar/spire-registration-template.sh \
    --tool-name mcp2cli \
    --env dev \
    --mode k8s \
    --namespace agents \
    --sa mcp2cli
```

Apply the registration via kubectl exec into the SPIRE Server pod:

```bash
kubectl -n spire-system exec spire-server-0 -- \
    /opt/spire/bin/spire-server entry create \
    -socketPath /tmp/spire-server/private/api.sock \
    -parentID spiffe://precinct.poc/agent/k8s-psat \
    -spiffeID spiffe://poc.local/agents/mcp-client/mcp2cli/dev \
    -selector k8s:ns:agents \
    -selector k8s:sa:mcp2cli
```

### 2. Create the Envoy ConfigMap

```bash
kubectl create configmap envoy-sidecar-config \
    --from-file=envoy.yaml=deploy/sidecar/envoy-sidecar.yaml \
    -n agents
```

Note: For K8s, update the gateway address in the ConfigMap to use the K8s service
DNS name. Edit `envoy-sidecar.yaml` and change the cluster address from
`precinct-gateway` to `precinct-gateway.gateway.svc.cluster.local` and port to
`9090`.

### 3. Patch your Deployment

```bash
kubectl patch deployment <your-tool> -n agents \
    --type strategic \
    --patch-file deploy/sidecar/k8s-sidecar-patch.yaml
```

Before patching, update the SPIFFE_ID env var in `k8s-sidecar-patch.yaml`:

```yaml
- name: SPIFFE_ID
  value: "spiffe://poc.local/agents/mcp-client/mcp2cli/dev"
```

### 4. Create the ServiceAccount

```bash
kubectl create serviceaccount mcp2cli -n agents
```

Ensure the Deployment uses this service account:

```yaml
spec:
  template:
    spec:
      serviceAccountName: mcp2cli
```

## SPIFFE ID Schema

All sidecar-injected tools follow the PRECINCT SPIFFE ID schema
(see `config/spiffe-ids.yaml`):

```
spiffe://<trust-domain>/agents/mcp-client/<tool-name>/<environment>
```

This maps to principal level 3 (agent) with capabilities: read, write, execute.
See `internal/gateway/middleware/principal.go` for the full mapping.

## Troubleshooting

### Verifying SVID issuance

**Docker Compose:**

```bash
# Check if the SPIRE entry exists
docker exec spire-server \
    /opt/spire/bin/spire-server entry show \
    -socketPath /tmp/spire-server/private/api.sock \
    | grep mcp2cli

# Check SPIRE agent logs for workload attestation
docker logs spire-agent 2>&1 | grep mcp2cli
```

**Kubernetes:**

```bash
# Check SPIRE registration entries
kubectl -n spire-system exec spire-server-0 -- \
    /opt/spire/bin/spire-server entry show \
    -socketPath /tmp/spire-server/private/api.sock \
    | grep mcp2cli

# Check SPIRE agent logs
kubectl -n spire-system logs -l app.kubernetes.io/name=spire-agent \
    | grep mcp2cli
```

### Checking Envoy sidecar health

```bash
# Envoy admin stats (from within the pod/container network)
curl http://127.0.0.1:9901/stats | grep sidecar_http

# Envoy cluster health
curl http://127.0.0.1:9901/clusters | grep precinct_gateway

# Check Envoy logs
docker logs envoy-sidecar 2>&1 | tail -20
# or in K8s:
kubectl logs <pod> -c envoy-sidecar | tail -20
```

### Verifying identity in audit logs

After sending a request through the sidecar, check the gateway audit log:

```bash
# Docker Compose
docker exec precinct-gateway cat /tmp/audit.jsonl | \
    jq 'select(.spiffe_id | contains("mcp2cli"))'

# K8s
kubectl logs -l app=precinct-gateway | \
    jq 'select(.spiffe_id | contains("mcp2cli"))'
```

### Common issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Missing X-SPIFFE-ID header` | SPIFFE_ID env var not set | Set `SPIFFE_ID` environment variable on the Envoy container |
| `401 Unauthorized` with valid header | SPIFFE ID not registered in SPIRE | Run `spire-registration-template.sh` and register the entry |
| `Connection refused` on 127.0.0.1:9090 | Network namespace not shared | Verify `network_mode: "service:envoy-sidecar"` in Compose or pod co-location in K8s |
| Envoy fails to start | Config file not mounted | Check volume mount for `envoy-sidecar.yaml` |
| Gateway unreachable from sidecar | Wrong network | Ensure envoy-sidecar is on `agentic-net` (Compose) or can reach the gateway service (K8s) |
| Principal level 5 (anonymous) | SPIFFE ID path prefix not recognized | Verify the SPIFFE ID starts with `agents/` to get level 3 (agent) principal |
