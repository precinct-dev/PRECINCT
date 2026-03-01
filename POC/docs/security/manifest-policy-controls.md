# Manifest Policy Controls (Prod vs Local)

This document defines the manifest hardening contract enforced by `make manifest-policy-check`.

## Production Controls

The production-intent gate enforces:

1. Digest-pinned production image references
   - Source of truth: `config/compose-production-intent.env`
   - Rule: all `PROD_*_IMAGE` values must be `@sha256` pinned and must not use `:latest`.

2. Kubernetes privileged-pattern restrictions for production manifests
   - Scope: `infra/eks/**` excluding `infra/eks/overlays/local/**`
   - Deny by default:
     - `Service.spec.type: NodePort`
     - `hostPath` volumes
     - `securityContext.privileged: true`
   - Exceptions are explicit and code-reviewed in `internal/manifestpolicy/checker.go`.

## Approved Exceptions

Exceptions are intentionally narrow and mapped to runtime requirements:

- `infra/eks/observability/phoenix/phoenix-service.yaml`
  - `NodePort` allowed for operator diagnostics UI access.

- SPIRE socket `hostPath` exceptions (workload identity plumbing):
  - `infra/eks/gateway/gateway-deployment.yaml`
  - `infra/eks/mcp-server/mcp-server-deployment.yaml`
  - `infra/eks/s3-mcp-server/s3-mcp-server-deployment.yaml`
  - `infra/eks/spike/keeper-deployment.yaml`
  - `infra/eks/spike/nexus-deployment.yaml`
  - `infra/eks/spike/seeder-job.yaml`
  - `infra/eks/spike/bootstrap-job.yaml`
  - `infra/eks/spire/agent-daemonset.yaml`

No `privileged: true` exceptions are currently approved.

## Local-Dev Exceptions

Local-dev ergonomics are intentionally separated from production controls:

- `infra/eks/overlays/local/**`
  - Can include NodePort/dev-only adjustments for local cluster access.
- `docker-compose.yml` and local image tags
  - Local stacks may use mutable tags for rapid iteration.
- Production checks are enforced through:
  - `docker-compose.prod-intent.yml`
  - `config/compose-production-intent.env`
  - `infra/eks/**` (excluding local overlay)

## CI Gate

CI must run:

1. `make security-scan`
2. `make manifest-policy-check`

Any manifest policy violation is a hard failure.
