# Security Policy

## Reporting a Vulnerability

PRECINCT is a security-critical project. If you discover a security
vulnerability, **do not open a public issue**.

### Preferred: GitHub Security Advisory

Report vulnerabilities privately via GitHub's security advisory feature:

https://github.com/precinct-dev/precinct/security/advisories/new

### Alternative: Email

If you cannot use GitHub advisories, email the maintainers directly at:

**security@precinct.dev**

### What to Include

- Description of the vulnerability
- Steps to reproduce (or proof-of-concept)
- Affected component (middleware layer, SDK, configuration, deployment)
- Severity assessment (your best estimate)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** depends on severity, but we aim for:
  - CRITICAL: patch within 72 hours
  - HIGH: patch within 14 days
  - MEDIUM/LOW: next scheduled release

### Scope

The following are in scope for security reports:

- Authentication/authorization bypass in the gateway middleware chain
- SPIFFE/SPIRE identity spoofing or impersonation
- OPA policy bypass or privilege escalation
- DLP scanner evasion
- Secret leakage from SPIKE token substitution
- Cryptographic weaknesses (JWT validation, Ed25519 attestation)
- Supply chain issues (dependency vulnerabilities, CI/CD compromise)

### Out of Scope

- Vulnerabilities in third-party dependencies that are already publicly disclosed
  (file a regular issue instead, referencing the CVE)
- Security issues in the mock/example services under `examples/`
- Denial of service against the local development Docker Compose stack

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (HEAD) | Yes |
| Tagged releases | Yes (latest only) |

## Dependency Updates

This project does not use automated dependency update bots (Dependabot, Renovate)
due to CI resource constraints. Dependencies are updated manually on a regular
cadence. If you are deploying PRECINCT, we recommend configuring your own
dependency monitoring using one of:

- [Dependabot](https://docs.github.com/en/code-security/dependabot)
- [Renovate](https://docs.renovatebot.com/)
- [Snyk](https://snyk.io/)
- `go list -m -u all` (manual check for Go module updates)

## Security Scanning

Every push to `main` runs the full security scan pipeline:

- **gosec** -- Go source code static analysis
- **trivy** -- Filesystem and container image CVE scanning
- **hadolint** -- Dockerfile linting
- **trufflehog** -- Secret detection

Results are available as CI artifacts. See `make security-scan` for local execution
and [docs/security/baseline.md](docs/security/baseline.md) for the current baseline.
