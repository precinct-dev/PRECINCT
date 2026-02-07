# SPIKE Nexus Deployment on EKS -- Agentic Reference Architecture POC

Kubernetes manifests for deploying SPIKE Nexus in token mode on the EKS cluster.

Story: RFA-9fv.3

## Prerequisites

1. **SPIRE deployed** (`make -C ../spire deploy` completed successfully)
2. **SPIRE registration entry** for SPIKE Nexus exists (created by `make -C ../spire deploy-entries`)
3. **kubectl** configured for the target cluster

## Architecture

```
+-----------------+
| SPIKE Nexus     |   Deployment (1 replica)
| Token Mode      |   SPIFFE ID: spiffe://agentic-ref-arch.poc/ns/spike-system/sa/spike-nexus
+--------+--------+
         |
         | mTLS via SVID
         |
+--------v--------+
| SPIRE Agent     |   Workload API socket
| (hostPath)      |   /run/spire/sockets/agent.sock
+-----------------+
```

SPIKE Nexus obtains its SPIFFE SVID from the SPIRE Agent Workload API and uses it to:
- Authenticate itself to other SPIFFE-aware workloads
- Issue short-lived tokens to workloads that present valid SVIDs
- Validate tokens for service-to-service authorization

## Deployment

```bash
cd POC/infra/eks/spike

# Deploy SPIKE Nexus
make deploy
```

## Verification

```bash
make verify
make status
make logs
```

## Validation (Without a Cluster)

```bash
make dry-run
```

## Teardown

```bash
make undeploy
```

## Files

| File | Purpose |
|------|---------|
| `namespace.yaml` | `spike-system` namespace with pod security labels |
| `nexus-configmap.yaml` | Nexus configuration (token mode, trust domain, SPIRE socket) |
| `nexus-rbac.yaml` | ServiceAccount for SPIFFE identity |
| `nexus-deployment.yaml` | Single-replica Deployment with SPIRE socket mount |
| `nexus-service.yaml` | ClusterIP service on port 8443 (HTTPS) |
| `Makefile` | Deployment, verification, and cleanup targets |

## Configuration

Environment variables (via ConfigMap):

| Variable | Value | Purpose |
|----------|-------|---------|
| `SPIKE_NEXUS_MODE` | `token` | Token-based authorization mode |
| `SPIKE_NEXUS_LOG_LEVEL` | `info` | Log verbosity |
| `SPIKE_NEXUS_ADDR` | `:8443` | Listen address (HTTPS) |
| `SPIKE_NEXUS_TRUST_DOMAIN` | `agentic-ref-arch.poc` | SPIFFE trust domain |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///run/spire/sockets/agent.sock` | SPIRE Workload API |

## Next Steps

- **RFA-9fv.4**: Configure gateway to use SPIKE for token issuance/validation
- **Production**: Add SPIKE Keepers for HA, configure token rotation policies
