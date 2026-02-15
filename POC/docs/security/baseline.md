# Security Scan Baseline

**As Of:** 2026-02-15
**Last Updated:** 2026-02-15
**Epic:** RFA-l6h6.7.5 (Security Evidence Hardening)

This document is the auditable baseline for security scan results and evidence provenance.
Baseline claims in this file must map to concrete machine-readable artifacts.

## Evidence Snapshot (2026-02-15)

Baseline evidence was collected with:

- `make security-scan`
- `make security-scan-validate`

Produced artifacts:

- Local manifest: `build/security-scan/latest/security-scan-manifest.json`
- Local per-scan summaries: `build/security-scan/latest/summaries/*.json`
- Local raw scan outputs: `build/security-scan/latest/raw/*.sarif`, `build/security-scan/latest/raw/*.json`
- Committed evidence snapshot: `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
- CI bundle source: `.github/workflows/security-scan.yml` uploads `security-scan-evidence-bundle`

## Scanning Tools

| Tool | Version | Scan Type | Baseline Result Count |
|------|---------|-----------|-----------------------|
| gosec | v2.21.4 | Go source code security analysis | 0 |
| trivy | 0.29.0+ | Filesystem dependency vulnerability scan | 0 |
| trivy | 0.29.0+ | Container image vulnerability scan | 0 |

## Baseline Findings

### gosec

- Baseline status: `pass`
- Baseline result count: `0`
- Evidence:
  - `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
  - `build/security-scan/latest/raw/gosec-results.sarif`

### trivy filesystem

- Baseline status: `pass`
- Baseline result count: `0`
- Evidence:
  - `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
  - `build/security-scan/latest/raw/trivy-fs-results.sarif`
  - `build/security-scan/latest/raw/trivy-fs-results.json`

### trivy image

- Baseline status: `pass`
- Baseline result count: `0`
- Evidence:
  - `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
  - `build/security-scan/latest/raw/trivy-image-results.sarif`
  - `build/security-scan/latest/raw/trivy-image-results.json`

## Accepted Risks

### AR-001: Development-Only Binaries in Repository

**Finding:** Compiled binaries (gateway, gdpr-delete, service) present in repository root.  
**Severity:** LOW  
**Rationale:** Development convenience. `.gitignore` prevents future binary commits.  
**Mitigation:** Binaries are rebuilt from source in CI. Production deployments use container images, not repository binaries.  
**Accepted:** 2026-02-06  
**Review Date:** 2026-05-06

### AR-002: Offline Vulnerability DB Drift

**Finding:** Trivy vulnerability database may be stale in offline environments.  
**Severity:** LOW  
**Rationale:** Offline operation is an explicit product requirement.  
**Mitigation:**

- CI scans run online and publish evidence artifacts.
- Developers refresh DB when back online (`trivy image --download-db-only`).
- Dependabot provides weekly dependency updates.

**Accepted:** 2026-02-06  
**Review Date:** Ongoing

## Readiness Gate

Production-intent readiness must use strict security evidence gates:

- `make security-scan-strict`
- `make security-scan-validate`
- `make production-readiness-validate`

These targets fail when required scan artifacts are missing, empty, or hash-mismatched against the generated manifest.

## References

- Security scan workflow: `.github/workflows/security-scan.yml`
- Local artifact collector: `scripts/security/collect-security-scan-artifacts.sh`
- Artifact validator: `tests/e2e/validate_security_scan_artifacts.sh`
- Committed snapshot: `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
