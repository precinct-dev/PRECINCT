# Security Scan Baseline

**Last Updated:** 2026-02-06
**Epic:** RFA-lo1.1 (Security Scanning Infrastructure)

This document establishes the security scanning baseline for the Agentic Reference Architecture. All findings documented here represent the state at the time of implementing automated security scanning (RFA-lo1.1).

## Purpose

This baseline serves to:

1. **Differentiate new vulnerabilities from known issues** - New findings in CI require investigation; baseline findings are tracked here
2. **Document accepted risks** - Some findings may be accepted due to false positives, low impact, or mitigation in place
3. **Track remediation progress** - Findings move from "accepted risk" to "remediated" as fixes are applied
4. **Provide audit trail** - Security teams can review rationale for accepted risks

## Scanning Tools

| Tool | Version | Scan Type | Frequency |
|------|---------|-----------|-----------|
| gosec | v2.21.4+ | Go source code security analysis | Every PR + push to main |
| trivy | 0.29.0+ | Container image CVE scanning | Every PR + push to main |
| trivy | 0.29.0+ | Filesystem dependency scanning | Every PR + push to main |

## Baseline Findings

### Go Source Code (gosec)

**Status at baseline:** No gosec scan performed during story RFA-lo1.1 implementation (gosec not installed on developer machine).

**Action:** First CI run will establish gosec baseline. Any findings will be documented here with accept/remediate decision.

**Expected categories to review:**
- G101: Hardcoded credentials (expect 0 - credentials are in environment variables)
- G104: Unhandled errors (will review and fix or accept with rationale)
- G304: File path injection (will review context - some file operations are admin-only)
- G402: TLS configuration (expect strong TLS config - verify settings)

### Container Images (trivy image)

**Status at baseline:** Container image not built during story RFA-lo1.1 implementation.

**Action:** First CI run will establish image baseline. Expected findings:

1. **Base image vulnerabilities (golang:1.23-alpine)**
   - **Accepted risk:** Using official Golang images. Updates applied via Dependabot weekly.
   - **Mitigation:** Multi-stage build - final image is distroless, contains only runtime binary.

2. **Go runtime CVEs**
   - **Threshold:** Only CRITICAL severity requires immediate action
   - **Mitigation:** Go version pinned in go.mod, updated weekly via Dependabot

**Acceptance criteria for image findings:**
- CRITICAL: Must remediate or document explicit acceptance within 7 days
- HIGH: Review and plan remediation within 30 days or accept with rationale
- MEDIUM/LOW: Review quarterly, accept if no exploit path exists

### Filesystem Dependencies (trivy fs)

**Status at baseline:** Scan in progress during implementation. Will document findings from first full scan.

**Expected findings:**

1. **Go module dependencies**
   - Managed via go.mod with Dependabot weekly updates
   - CRITICAL/HIGH vulnerabilities in direct dependencies: remediate immediately
   - Transitive dependencies: evaluate exploit path, may accept if unexploitable

2. **Docker base image references**
   - golang:1.23-alpine (build stage)
   - gcr.io/distroless/static-debian12:nonroot (runtime stage)
   - Managed via Dependabot weekly updates

3. **Python dependencies (tools/compliance/)**
   - Limited scope: compliance report generation only
   - Not exposed to untrusted input
   - Managed via requirements.txt with Dependabot

## Accepted Risks

### AR-001: Development-Only Binaries in Repository

**Finding:** Compiled binaries (gateway, gdpr-delete, service) present in repository root.
**Severity:** LOW
**Rationale:** Development convenience. .gitignore updated to prevent future commits of binaries.
**Mitigation:** Binaries are rebuilt from source in CI. Production deployments use container images, not repository binaries.
**Accepted:** 2026-02-06
**Review Date:** 2026-05-06 (quarterly)

### AR-002: Offline Capability Delays Vulnerability Database Updates

**Finding:** Trivy vulnerability database may be stale in offline development environments (BUSINESS.md 5.5).
**Severity:** LOW
**Rationale:** Offline capability is a documented requirement. Developers working offline accept stale CVE data.
**Mitigation:**
- CI always runs with latest trivy database (online environment)
- Developers should run `trivy image --download-db-only` when returning online
- Weekly Dependabot PRs ensure dependencies are current

**Accepted:** 2026-02-06
**Review Date:** Ongoing (acceptable trade-off for offline support)

## Remediation Tracking

| Finding ID | Tool | Severity | Description | Status | Target Date | Notes |
|------------|------|----------|-------------|--------|-------------|-------|
| (none yet) | - | - | - | - | - | First CI run will populate this table |

## Baseline Update Process

This baseline is updated when:

1. **New tools added** - Document tool version, scan type, expected findings
2. **New findings accepted** - Add to "Accepted Risks" with rationale and review date
3. **Findings remediated** - Move from "Accepted Risks" to "Remediated" section below
4. **Quarterly review** - Re-evaluate accepted risks, update review dates

## Remediated Findings

(None yet - first baseline)

## Next Steps

1. **First CI run** - Workflow .github/workflows/security-scan.yml will run on next PR
2. **Review findings** - Triage gosec, trivy-image, trivy-fs results
3. **Update baseline** - Document all findings with accept/remediate decision
4. **Integrate with backlog** - Create stories for remediation work
5. **Weekly Dependabot PRs** - Review and merge dependency updates

## References

- Security scanning workflow: `.github/workflows/security-scan.yml`
- Dependabot config: `.github/dependabot.yml`
- Makefile target: `make security-scan`
- Tool prerequisites: `docs/getting-started/prerequisites.md`
- Business requirements: `docs/BUSINESS.md` (Section 5.5: Offline Capability)
