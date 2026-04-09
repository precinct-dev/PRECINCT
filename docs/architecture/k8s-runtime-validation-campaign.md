# K8s Runtime Validation Campaign (v2.4)

This campaign validates the v2.4 runtime control planes on Kubernetes with
explicit allow/deny checks and machine-readable evidence output.

## Scope

- Runtime target: Kubernetes (local Docker Desktop cluster for reference validation)
- Control planes: ingress, context, model, tool, loop
- Expected behavior per plane: at least one allow and one deny result
- Evidence output: per-control pass/fail JSON report

## Checklist

| Control Plane | Allow Check | Deny Check | Expected Outcome |
|---|---|---|---|
| Ingress | Authenticated connector submit | Revoked connector submit | `INGRESS_ALLOW` / `INGRESS_SOURCE_UNAUTHENTICATED` |
| Context | Context admit with clean scan flags | Context admit with failed scan flags | `CONTEXT_ALLOW` / `CONTEXT_NO_SCAN_NO_SEND` |
| Model | Mediated model call | Direct egress model call | `MODEL_ALLOW` / `MODEL_PROVIDER_DIRECT_EGRESS_BLOCKED` |
| Tool | Approved capability execution | Unapproved capability execution | `TOOL_ALLOW` / `TOOL_CAPABILITY_DENIED` |
| Loop | Limits within policy | Limits exceeded | `LOOP_ALLOW` / `LOOP_HALT_MAX_STEPS` |

## Execution Commands

Run from repository root:

```bash
k8s-up
k8s-runtime-campaign
demo-k8s
```

## Evidence Artifacts

- Runtime campaign report (machine-readable):
  - Runtime output: `build/validation/k8s-runtime-validation-report.v2.4.json`
  - Checked-in artifact snapshot:
    `docs/architecture/artifacts/k8s-runtime-validation-report.v2.4.json`
- Compose portability/backport decisions:
  `docs/architecture/artifacts/compose-backport-decision-ledger.v2.4.json`

The JSON report is authoritative for campaign pass/fail per control plane.
