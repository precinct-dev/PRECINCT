# OpenClaw v2.4 Walking Skeleton Integration Guide

This guide defines the minimal change set to route OpenClaw traffic through the
UASGS v2.4 control planes without changing OpenClaw's normal interaction model.

## Objective

- Keep OpenClaw behavior stable for end users.
- Enforce mediated model and governed tool execution through the gateway.
- Preserve ingress/context contracts with deterministic, auditable deny paths.

## Minimal Required OpenClaw Changes

1. Add a thin request adapter that emits v2.4 contract payloads for:
   - `ingress.admit` (`/v1/ingress/submit`)
   - `context.admit` (`/v1/context/admit`)
   - `model.call` (`/v1/model/call`)
   - `tool.execute` (`/v1/tool/execute`)
2. Attach per-request envelope fields:
   - `run_id`, `session_id`, `tenant`, `actor_spiffe_id`, `plane`
3. Route model and tool operations through the gateway only.
   - No direct model-provider egress from OpenClaw runtime.
4. Preserve deny handling by forwarding canonical reason codes to logs/telemetry.

Reference adapter implementation in this repo:
- `internal/integrations/openclaw/adapter.go`

## Security Outcomes Enforced

- Allowed path:
  - ingress accepted (`INGRESS_ALLOW`)
  - context/memory admitted (`CONTEXT_ALLOW`)
  - mediated model call allowed (`MODEL_ALLOW`)
  - governed tool call allowed (`TOOL_ALLOW`)
- Denied path:
  - direct model egress blocked (`MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED`)
  - unapproved tool capability blocked (`TOOL_CAPABILITY_DENIED`)

## Validation Commands

Run from repository root:

```bash
go test ./internal/integrations/openclaw/... -count=1
go test ./tests/integration/... -run OpenClawWalkingSkeleton -count=1
bash POC/tests/e2e/scenario_j_openclaw_walking_skeleton.sh
```

E2E artifact output:
- `POC/tests/e2e/artifacts/scenario_j_<run_id>.json`
- Checked-in snapshot:
  `POC/docs/integrations/artifacts/openclaw-walking-skeleton-report.v1.json`

## Notes

- This is a walking skeleton integration slice, not full OpenClaw feature parity.
- The adapter intentionally isolates v2.4 contract shape from OpenClaw internals
  so OpenClaw can evolve without control-plane regressions.
