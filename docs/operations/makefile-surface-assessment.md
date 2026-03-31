# Makefile Surface Assessment

Date: 2026-03-31

## Scope

The root [`Makefile`](/Users/ramirosalas/workspace/PRECINCT/Makefile) currently exposes:

- 55 visible targets in `make help`
- 62 hidden callable targets

This assessment treats the `Makefile` as an operator and developer UX surface, not just a task runner.

## Recommended Principles

- Keep top-level visible targets for stable day-to-day workflows only.
- Keep specialist validation and runbook-proof targets callable, but hidden.
- Remove aliases that only preserve old naming and do not add behavior.
- Prefer aggregate targets for common workflows and leaf targets for expert debugging only.

## Keep

These are the right kind of top-level targets and should remain visible:

- Core lifecycle: `help`, `up`, `down`, `clean`, `repave`, `logs`
- Observability: `phoenix-up`, `phoenix-down`, `phoenix-reset`, `opensearch-up`, `opensearch-down`, `opensearch-reset`, `opensearch-seed`, `opensearch-validate`, `observability-up`, `observability-down`, `observability-reset`
- Quality and build: `lint`, `test`, `test-unit`, `test-integration`, `test-opa`, `test-cli`, `test-mcpserver-integration`, `test-x509pop-restart`, `test-e2e`, `build`, `build-cli`, `install`
- Demo entrypoints: `demo`, `demo-compose`, `demo-compose-mock`, `demo-k8s`, `demo-cli`, `demo-sidecar`, `openclaw-demo`
- Kubernetes: `k8s-up`, `k8s-down`, `k8s-opensearch-up`, `k8s-opensearch-down`, `k8s-sync-config`, `k8s-check-config`, `k8s-validate`
- Release and readiness: `validate`, `production-readiness-validate`, `upgrade-check`, `upgrade`, `upgrade-all`

## Consolidate

These targets still serve a purpose, but the surface is more fragmented than it needs to be:

- `compose-down`
  Recommendation: fold into `down` with a flag like `VOLUMES=1`, or rename to something clearer like `down-volumes`
  Reason: it overlaps with `down` and partially overlaps with `clean`

- `story-evidence-validate`, `tracker-surface-validate`, `readiness-state-validate`
  Recommendation: keep callable, but hide them from `make help`
  Reason: they are specialist release/readiness checks rather than primary developer entrypoints

- Hidden demo leaf targets:
  `precinct-demo`, `precinct-operate-demo`, `compliance-demo`, `repave-demo`, `upgrade-demo`, `demo-compose-strict-observability`, `demo-extensions`
  Recommendation: keep hidden or move to `tests/e2e/` wrappers; do not promote them back to the visible surface
  Reason: they are implementation details behind `demo`, `demo-compose`, and `demo-cli`

- Hidden validation leaf targets:
  `compose-production-intent-preflight`, `compose-production-intent-preflight-signature-prereqs`, `compose-production-intent-validate`, `operations-readiness-validate`, `managed-cloud-bootstrap-prereqs-validate`, `framework-taxonomy-mappings-validate`, `app-pack-model-validate`, `app-integration-strategy-docs-validate`, `gateway-bypass-case26-validate`, `observability-evidence-gate-validate`, `spike-shamir-validate`, `strict-runtime-validate`, `strict-overlay-operationalization-validate`, `k8s-overlay-digest-validate`, `promotion-identity-validate`, `ci-gate-parity-validate`, `local-k8s-runtime-campaign-artifacts-validate`, `production-reality-closure-local-artifacts-validate`
  Recommendation: keep hidden, but group/document them as expert validation leaves under `validate`
  Reason: they are valuable for forensic or runbook proof work, but too numerous for the main help surface

- Hidden security and compliance leaves:
  `security-scan`, `security-scan-strict`, `security-scan-validate`, `manifest-policy-check`, `control-matrix-check`, `compliance-report`, `compliance-evidence`, `test-compliance`, `gdpr-ropa`, `gdpr-delete`
  Recommendation: keep hidden and document them as expert/audit workflows
  Reason: they are useful, but not part of the default day-to-day operator loop

## Remove

These are the clearest redundancy candidates:

- `k8s-local-up`
- `k8s-local-down`
- `k8s-local-opensearch-up`
- `k8s-local-opensearch-down`

Reason: they are pure aliases with no added behavior. They only preserve old terminology.

- `clean-logs`

Reason: this is a tiny helper, not a top-level workflow. If it is still needed, move it to a script or hide it behind a better-named maintenance target.

## Important Constraint Before Pruning

Some hidden and alias targets are still referenced by docs, runbooks, tests, and site pages. The biggest examples are:

- `compose-production-intent-preflight`
- `strict-runtime-validate`
- `security-scan-strict`
- `demo-compose-strict-observability`
- `k8s-local-up` and related aliases

That means removal should happen with a documentation sweep in the same change, not piecemeal.

## Recommended Cleanup Order

1. Remove the `k8s-local-*` aliases and update docs/runbooks to the canonical `k8s-*` names.
2. Hide `story-evidence-validate`, `tracker-surface-validate`, and `readiness-state-validate` from `make help`.
3. Replace `compose-down` with either `down VOLUMES=1` or a clearer canonical name.
4. Keep the hidden validation and audit leaves, but document them as expert/debug targets rather than top-level workflows.
