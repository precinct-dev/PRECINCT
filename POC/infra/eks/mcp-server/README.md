# MCP Tool Server - EKS Deployment

Story: RFA-9fv.4

## Architecture

The MCP tool server runs in the `tools` namespace and receives JSON-RPC
requests from the PRECINCT Gateway. In the Docker Compose POC, the Docker
MCP server is managed by Docker Desktop's MCP Toolkit. In EKS, we deploy it
as a regular container.

### Deployment Options

| Option | Image | Use Case |
|--------|-------|----------|
| Placeholder (default) | `python:3.12-slim` | Testing connectivity and NetworkPolicies |
| Docker MCP Gateway | `docker/mcp-gateway` | Integration with Docker MCP Toolkit |
| Custom MCP Server | Your image | Production tool execution |

The placeholder server responds to health checks (GET) and echoes JSON-RPC
requests (POST) with valid responses, enabling gateway connectivity testing
without a real MCP tool implementation.

### SPIFFE Identity

All tool servers in the `tools` namespace share the ServiceAccount `mcp-tool`,
which maps to SPIFFE ID:

```
spiffe://precinct.poc/ns/tools/sa/mcp-tool
```

For production, consider per-tool ServiceAccounts for finer-grained identity.

## Quick Reference

```bash
# Deploy
make deploy

# Check health
make verify

# View logs
make logs

# Validate manifests offline
make dry-run

# Remove
make undeploy
```

## Manifest Files

| File | Resource | Description |
|------|----------|-------------|
| `mcp-server-namespace.yaml` | Namespace | `tools` namespace with pod security standards |
| `mcp-server-rbac.yaml` | ServiceAccount | `mcp-tool` identity for SPIFFE attestation |
| `mcp-server-deployment.yaml` | Deployment | Tool server pod (placeholder by default) |
| `mcp-server-service.yaml` | Service | ClusterIP on port 8081 |

## Replacing the Placeholder

To use a real MCP tool server, edit `mcp-server-deployment.yaml`:

```yaml
# Replace the placeholder image and command:
containers:
  - name: mcp-server
    image: <your-ecr-registry>/mcp-tool-server:latest
    ports:
      - name: jsonrpc
        containerPort: 8081
```

Then redeploy:

```bash
make undeploy && make deploy
```
