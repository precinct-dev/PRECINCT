# Security Evidence Collection

This guide explains how to collect and validate security scan evidence for production-readiness reviews.

## Local Collection

Generate scan artifacts:

```bash
make security-scan
```

Validate artifact completeness + integrity:

```bash
make security-scan-validate
```

Validate threat-model control coverage + reviewer report generation:

```bash
make control-matrix-check
```

Run strict gate (required for production-intent readiness checks):

```bash
make security-scan-strict
make security-scan-validate
```

## Artifact Layout

Default output directory:

- `build/security-scan/latest/`

Expected files:

- `security-scan-manifest.json`
- `raw/gosec-results.sarif`
- `raw/trivy-fs-results.sarif`
- `raw/trivy-fs-results.json`
- `raw/trivy-image-results.sarif`
- `raw/trivy-image-results.json`
- `summaries/gosec-summary.json`
- `summaries/trivy-fs-summary.json`
- `summaries/trivy-image-summary.json`
- `control-verification-report.json`
- `control-verification-report.md`

## How to Interpret the Manifest

`security-scan-manifest.json` is the source of truth for evidence review.

- `scans.<name>.status`: `pass`, `failed`, or `skipped`
- `scans.<name>.result_count`: number of SARIF findings
- `artifacts[]`: per-file SHA-256 + size for immutability checks

Production-intent validation requires all scan statuses to be `pass`.

## CI Collection

Workflow: `.github/workflows/security-scan.yml`

Manual workflow uploads (when explicitly run):

- per-scan artifacts (`gosec-results`, `trivy-fs-results`, `trivy-image-results`)
- consolidated evidence bundle (`security-scan-evidence-bundle`)

The summary job validates required files before publishing the consolidated bundle.

Policy note:

- GitHub workflows are configured as `workflow_dispatch` only to avoid automatic CI spend.
- Production-readiness evidence for this repository is collected primarily via local make/demo gates.

## CI Readiness Gate Policy (RFA-l6h6.8.4)

Workflow: `.github/workflows/ci.yaml`

Manual workflow gates:

- `readiness-gates`
  - `make strict-runtime-validate`
  - `make production-readiness-validate`
  - uploads artifact: `readiness-gates` (strict runtime + security evidence logs and manifest bundle)
- `demo-compose-gate`
  - `make phoenix-up`
  - `make demo-compose`
  - uploads artifact: `demo-compose-gate` (demo logs + compose diagnostics)

Manual policy gate:

- `k8s-validation-policy-gate`
  - runs on `workflow_dispatch`
  - `make k8s-validate`
  - uploads artifact: `k8s-validation-policy-gate`

Rationale:

- Workflows are manual-only to prevent automatic runner usage.
- Equivalent quality/safety gates are executed locally via make targets and demo scripts.
- `readiness-state-validate` remains an operator control because it requires live `nd` state access.

## Failure Semantics

The validator fails when:

- required artifact files are missing or empty
- manifest entries are missing
- artifact SHA-256 does not match manifest
- strict mode is requested and any scan is skipped/failed
- control matrix coverage is missing for security/usability/blind-spot domains
- required matrix evidence is missing or stale
