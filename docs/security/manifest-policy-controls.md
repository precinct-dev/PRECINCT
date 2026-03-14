# Manifest Policy Controls (Prod vs Local)

This document defines the manifest hardening contract enforced by `make manifest-policy-check`.

## Production Controls

The production-intent gate enforces:

1. Digest-pinned production image references
   - Source of truth: `config/compose-production-intent.env`
   - Rule: all `PROD_*_IMAGE` values must be `@sha256` pinned and must not use `:latest`.

2. Kubernetes privileged-pattern restrictions for production manifests
   - Scope: `deploy/terraform/**` excluding `deploy/terraform/overlays/local/**`
   - Deny by default:
     - `Service.spec.type: NodePort`
     - `hostPath` volumes
     - `securityContext.privileged: true`
   - Exceptions are explicit and code-reviewed in `internal/manifestpolicy/checker.go`.

## Approved Exceptions

Exceptions are intentionally narrow and mapped to runtime requirements:

- `deploy/terraform/observability/phoenix/phoenix-service.yaml`
  - `NodePort` allowed for operator diagnostics UI access.

- SPIRE socket `hostPath` exceptions (workload identity plumbing):
  - `deploy/terraform/gateway/gateway-deployment.yaml`
  - `deploy/terraform/mcp-server/mcp-server-deployment.yaml`
  - `deploy/terraform/s3-mcp-server/s3-mcp-server-deployment.yaml`
  - `deploy/terraform/spike/keeper-deployment.yaml`
  - `deploy/terraform/spike/nexus-deployment.yaml`
  - `deploy/terraform/spike/seeder-job.yaml`
  - `deploy/terraform/spike/bootstrap-job.yaml`
  - `deploy/terraform/spire/agent-daemonset.yaml`

No `privileged: true` exceptions are currently approved.

## Local-Dev Exceptions

Local-dev ergonomics are intentionally separated from production controls:

- `deploy/terraform/overlays/local/**`
  - Can include NodePort/dev-only adjustments for local cluster access.
- `docker-compose.yml` and local image tags
  - Local stacks may use mutable tags for rapid iteration.
- Production checks are enforced through:
  - `docker-compose.prod-intent.yml`
  - `config/compose-production-intent.env`
  - `deploy/terraform/**` (excluding local overlay)

## CI Gate

CI must run:

1. `make security-scan`
2. `make manifest-policy-check`

Any manifest policy violation is a hard failure.
