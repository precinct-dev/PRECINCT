# Security Scan Baseline

**As Of:** 2026-04-02
**Last Updated:** 2026-04-02
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
- CI bundle source: `.github/workflows/ci.yaml` uploads `security-scan-evidence-bundle`

## Scanning Tools

| Tool | Version | Scan Type | Baseline Result Count |
|------|---------|-----------|-----------------------|
| gosec | v2.25.0 | Go source code security analysis | 0 |
| trivy | v0.69.3 | Filesystem dependency vulnerability scan | 0 |
| trivy | v0.69.3 | Container image vulnerability scan | 0 |
| trufflehog | v3.94.2 | Filesystem secret scan | 0 |
| hadolint | v2.14.0 | Dockerfile linting | 11 (10 warning, 1 info) |

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

### trufflehog

- Baseline status: `pass`
- Baseline result count: `0`
- Evidence:
  - `build/security-scan/latest/raw/trufflehog-results.jsonl`

### hadolint

- Baseline status: `pass`
- Baseline result count: `11` (10 warning, 1 info)
- Findings breakdown:
  - DL3018 x9 (warning): Unpinned versions in `apk add` within builder stages. Non-exploitable -- packages are consumed only during multi-stage build; final images use distroless base with no package manager.
  - DL3059 x1 (info): Consecutive RUN instructions in `Dockerfile.gateway`. Style suggestion only.
  - DL3003 x1 (warning): `cd` instead of `WORKDIR` in `examples/python/Dockerfile`.
- Evidence:
  - `build/security-scan/latest/raw/hadolint-results.sarif`

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

## Architectural Security Controls

The following controls address threat patterns validated by external research (Shapira et al., 2026, *Agents of Chaos*, arXiv:2602.20021v1).

### Channel Mediation

**Purpose:** Prevent prompt injection via unmediated external channels and unbounded resource consumption.

**Implementation:**

- Middleware chain step 7 (DLP) and step 10 (deep scan) route all channel content through security pipeline
- Ed25519 signature verification for webhook and event-driven ingress
- Content normalization before agent ingestion

**Evidence:**

- DLP middleware: `internal/gateway/middleware/dlp.go`
- Deep scan middleware: `internal/gateway/middleware/deep_scan.go`
- Middleware chain ordering: `internal/gateway/gateway.go`

### Data Source Integrity

**Purpose:** Prevent external data poisoning and rug-pull attacks where data sources change after initial verification.

**Implementation:**

- Middleware chain step 5 (tool registry verification) enforces hash verification per DataSourceDefinition struct
- MutablePolicy enforcement: mutable sources trigger re-verification on each access
- Digest logging for external data fetches

**Evidence:**

- Tool registry middleware: `internal/gateway/middleware/tool_registry.go`
- DataSourceDefinition struct and MutablePolicy: `internal/gateway/middleware/tool_registry.go`

### Escalation Detection

**Purpose:** Detect and prevent progressive concession accumulation and gradual privilege escalation.

**Implementation:**

- Middleware chain step 8 (session context) tracks cumulative escalation
- EscalationScore formula: Impact x (4 - Reversibility)
- Three-tier threshold system: Warning=15, Critical=25, Emergency=40
- RecordEscalation() function accumulates score across session

**Evidence:**

- Session context middleware: `internal/gateway/middleware/session_context.go`
- Escalation scoring and RecordEscalation(): `internal/gateway/middleware/session_context.go`

### Principal Hierarchy

**Purpose:** Prevent identity spoofing via authority confusion across trust boundaries.

**Implementation:**

- Middleware chain step 3 (SPIFFE auth) performs SPIFFE-to-role resolution
- X-Precinct-Principal-Level header injected by gateway for downstream policy decisions
- OPA authorization incorporates principal level for least-privilege enforcement

**Evidence:**

- SPIFFE auth middleware: `internal/gateway/middleware/spiffe_auth.go`
- X-Precinct-Principal-Level header enrichment: `internal/gateway/middleware/spiffe_auth.go`
- OPA policy incorporating principal level: `config/opa/mcp_policy.rego`

### Irreversibility Gating

**Purpose:** Prevent execution of irreversible actions without adequate oversight.

**Implementation:**

- Middleware chain step 9 (step-up gating) classifies action destructiveness
- ClassifyActionDestructiveness() taxonomy categorizes actions by reversibility
- Automatic step-up authentication for critical/irreversible classifications
- Human-in-the-loop approval required for irreversible action classes

**Evidence:**

- Step-up gating middleware: `internal/gateway/middleware/step_up_gating.go`
- ClassifyActionDestructiveness function: `internal/gateway/middleware/step_up_gating.go`
- Audit logging of destructiveness classification: `internal/gateway/middleware/audit.go`

## Readiness Gate

Production-intent readiness must use strict security evidence gates:

- `make security-scan-strict`
- `make security-scan-validate`
- `make production-readiness-validate`

These targets fail when required scan artifacts are missing, empty, or hash-mismatched against the generated manifest.

## References

- Security scan workflow: `.github/workflows/ci.yaml` (`security` job)
- Local artifact collector: `scripts/security/collect-security-scan-artifacts.sh`
- Artifact validator: `tests/e2e/validate_security_scan_artifacts.sh`
- Committed snapshot: `docs/security/artifacts/security-scan-evidence-2026-02-15.json`
