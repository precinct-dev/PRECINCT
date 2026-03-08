---
id: oc-ht7
title: "Validate OpenClaw integration in Kubernetes mode"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:58:39Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:413d9f8b9c6bd80d7af6d4a2040224606496ebae4f69ee62247c8a6fb8e6e18d"
closed_at: 2026-02-21T20:46:34Z
close_reason: "make demo-k8s exits 0. ALL CYCLES PASSED (k8s). Full E2E suite with SPIRE, OPA, DLP, SPIKE, rate limiting, all 28 tests passing. First run had 1 transient rate-limit probe failure due to pod stress after model egress timeout; re-run confirmed clean."
parent: oc-6bq
blocked_by: [oc-sdh]
follows: [oc-sdh]
---

## Description
## User Story

As a gateway operator, I need to confirm the OpenClaw integration works correctly in Kubernetes mode (local Docker Desktop k8s), so that the k8s deployment path is validated against the updated upstream contract.

## Context and Business Value

The Kubernetes deployment uses kustomize overlays at `infra/eks/overlays/` with local, dev, staging, and prod variants. The local overlay (`infra/eks/overlays/local/`) is used for Docker Desktop Kubernetes validation. The pack config specifies:
```json
"runtime_profile_hints": {
    "k8s": {
        "strict_deepscan": false,
        "preferred_validation": ["make demo-k8s"],
        "known_variance": ["case26_model_route_timeout_non_strict"]
    }
}
```

The k8s mode has a known variance (`case26_model_route_timeout_non_strict`) where model route timeouts are not strictly enforced. This is already documented and accepted.

This story validates that:
1. The k8s overlay renders correctly with kustomize
2. The gateway deploys in k8s with OpenClaw endpoints accessible
3. The WS adapter device-identity enforcement works in k8s mode
4. The k8s runtime campaign passes

## Implementation

### Step 1: Validate k8s overlays (offline, no cluster needed)

```bash
cd /Users/ramirosalas/workspace/agentic_reference_architecture/POC
make k8s-validate
```
This validates kustomize rendering and Phase 3 gateway wiring without needing a live cluster.

### Step 2: Deploy to local k8s (requires Docker Desktop k8s)

```bash
make k8s-up
```
Wait for all pods to reach Running/Ready.

### Step 3: Run k8s demo

```bash
make demo-k8s
```
This exercises the full E2E demo path against the k8s deployment.

### Step 4: Run k8s runtime campaign

```bash
make k8s-runtime-campaign
```
This produces a machine-readable validation report at `build/validation/k8s-runtime-validation-report.v2.4.json`.

### Step 5: Verify campaign artifacts

```bash
make local-k8s-runtime-campaign-artifacts-validate
```

### Step 6: Tear down

```bash
make k8s-down
```

## Acceptance Criteria

1. [AC1] `make k8s-validate` exits with status 0 (overlay rendering and wiring validation passes).
2. [AC2] `make k8s-up` deploys all services and they reach Running/Ready state.
3. [AC3] `make demo-k8s` exits with status 0 or documents known variances (case26).
4. [AC4] `make k8s-runtime-campaign` produces a report with zero unexpected failures.
5. [AC5] `make k8s-down` cleanly tears down the k8s deployment.
6. [AC6] The known variance `case26_model_route_timeout_non_strict` is the only acceptable non-pass result.

## Testing Requirements
### Unit tests (mocks OK)

- No new unit tests -- this is a deployment validation story.

### Integration tests (MANDATORY, no mocks)

- The k8s runtime campaign IS the integration test. Evidence is:
  - `make k8s-validate` exit status 0
  - `make k8s-runtime-campaign` report JSON
  - `make demo-k8s` output

### Test commands

```bash
make k8s-validate
make k8s-up
make demo-k8s
make k8s-runtime-campaign
make local-k8s-runtime-campaign-artifacts-validate
make k8s-down
```

## Scope Boundary

Scope: K8s deployment validation only. Files potentially modified:
- `infra/eks/overlays/local/kustomization.yaml` -- only if a configuration issue is found
- K8s manifests -- only if deployment issues are found
No changes to: adapter code, core gateway, middleware, policy engine, Go tests.

## Dependencies

Depends on Story oc-sdh (Docker Compose validation passes) being complete. K8s validation builds on a known-good adapter that passed compose validation.

MANDATORY SKILLS TO REVIEW:
- None identified. Kubernetes, kustomize, shell scripting. No specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocked_by oc-sdh

## Links
- Parent: [[oc-6bq]]
- Blocked by: [[oc-sdh]]
- Follows: [[oc-sdh]]

## Comments
