# SPIKE Keeper + Nexus Runtime on EKS -- PRECINCT POC

Kubernetes manifests for deploying the release-facing SPIKE keeper+nexus runtime
on Kubernetes. This bundle defaults to `2-of-3` Shamir recovery across
`spike-keeper-1`, `spike-keeper-2`, and `spike-keeper-3`.

Story: RFA-9fv.3

## Prerequisites

1. **SPIRE deployed** (`make -C ../spire deploy` completed successfully)
2. **SPIRE registration entry** for SPIKE Nexus exists (created by `make -C ../spire deploy-entries`)
3. **kubectl** configured for the target cluster

## Architecture

```
+-----------------+
| SPIKE Nexus     |   Deployment (1 replica)
| Token Mode      |   Root key recovery needs 2 keeper shards
+--------+--------+
         |
         | mTLS via SVID
         |
+--------v-----------------------------+
| SPIKE Keepers 1 / 2 / 3              |
| Independent shard holders            |
+--------+-----------------------------+
         |
         | Workload API socket
         |
+--------v--------+
| SPIRE Agent     |   /run/spire/sockets/agent.sock
+-----------------+
```

SPIKE Nexus obtains its SPIFFE SVID from the SPIRE Agent Workload API and uses it to:
- Authenticate itself to other SPIFFE-aware workloads
- Issue short-lived tokens to workloads that present valid SVIDs
- Validate tokens for service-to-service authorization

## Deployment

```bash
cd POC/infra/eks/spike

# Deploy keeper+nexus runtime surfaces
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
| `nexus-configmap.yaml` | Nexus configuration, including the release-facing keeper peer list |
| `keeper-deployment.yaml` | Keeper 1 deployment |
| `keeper-2-deployment.yaml` | Keeper 2 deployment |
| `keeper-3-deployment.yaml` | Keeper 3 deployment |
| `nexus-rbac.yaml` | ServiceAccount for SPIFFE identity |
| `nexus-deployment.yaml` | Single-replica Deployment with SPIRE socket mount |
| `nexus-service.yaml` | ClusterIP service on port 8443 (HTTPS) |
| `Makefile` | Deployment, verification, and cleanup targets |

## Configuration

Environment variables (via ConfigMap):

| Variable | Value | Purpose |
|----------|-------|---------|
| `SPIKE_NEXUS_KEEPER_PEERS` | `keeper-1,keeper-2,keeper-3` | Release-facing keeper peer list |
| `SPIKE_NEXUS_SHAMIR_THRESHOLD` | `2` | Minimum keeper shards required |
| `SPIKE_NEXUS_SHAMIR_SHARES` | `3` | Total keeper shards |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///run/spire/sockets/agent.sock` | SPIRE Workload API |

## Next Steps

- **RFA-9fv.4**: Configure gateway to use SPIKE for token issuance/validation
- **Local demo exception**: `infra/eks/overlays/local` patches this bundle back to `1-of-1` and removes keeper-2/3.
- **Validation**: Run `make -C ../../.. spike-shamir-validate` to verify the demo-versus-release keeper split.
