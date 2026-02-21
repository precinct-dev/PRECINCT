# Current State and Roadmap

**As Of:** 2026-02-16
**Last Updated:** 2026-02-16
**Branch:** main (all epic branches merged and deleted)
**Reference Architecture Version:** 2.4

---

## 0. As-Built Snapshot (2026-02-16)

This document is a live status summary. Historical implementation detail is preserved
below, but current planning truth is tracked by the active beads backlog and accepted
story evidence.

Current production-readiness closure status (`RFA-l6h6.7`) is tracked in:

- `docs/status/production-readiness-state.json` (authoritative as-of snapshot)
- `tests/e2e/validate_readiness_state_integrity.sh` (deterministic drift validator against live `bd`)

Current story-state snapshot (as-of 2026-02-16):

| Story | Status | Date Reference | Notes |
|-------|--------|----------------|-------|
| `RFA-l6h6.7.1` | closed | closed 2026-02-14 | strict MCP transport hardening accepted |
| `RFA-l6h6.7.2` | closed | closed 2026-02-14 | strict runtime wiring accepted (K8s + Compose) |
| `RFA-l6h6.7.3` | closed | closed 2026-02-14 | JSON-RPC correlation safety accepted |
| `RFA-l6h6.7.4` | closed | closed 2026-02-14 | strict attestation fail-closed wiring accepted |
| `RFA-l6h6.7.5` | closed | closed 2026-02-14 | security evidence hardening accepted |
| `RFA-l6h6.7.6` | closed | closed 2026-02-14 | docs/state integrity and release-gate validation accepted |
| `RFA-l6h6.7.7` | closed | closed 2026-02-14 | final strict Compose + K8s campaign accepted |
| `RFA-l6h6.6.10` | closed | closed 2026-02-16 | External-app full-port execution accepted; framework-gap reassessment completed in `RFA-l6h6.6.17.1` |

Known residual risks:

1. EKS remains offline-validated; no live cloud deployment evidence is captured in this repository.
2. Security-scan automation wiring is restored, but this repo snapshot does not include a hosted GitHub Actions run artifact link.
3. Epic `RFA-l6h6.7` is accepted/closed; external-app full-port execution (`RFA-l6h6.6.10`) and framework-gap closure reassessment (`RFA-l6h6.6.17.1`) are accepted/closed with post-gap rerun evidence (`run_all` fail=0).
4. Latest-source external-app validation cycle reran on 2026-02-16 (`RFA-t1hb`) with `run_all` -> `105 pass / 0 fail / 3 skip` and targeted case-study campaign -> `4 pass / 0 fail`.
5. Latest-source external-app runtime follow-up bug `RFA-655e` is accepted/closed; final latest-source decision package remains **GO** with no unresolved follow-up gaps.

Claim reconciliation summary:

| Prior claim | Corrected as-built statement | Evidence source |
|------------|------------------------------|-----------------|
| “The project is development-complete.” | Production-readiness closure epic `RFA-l6h6.7` is accepted and closed. | beads epic `RFA-l6h6.7` |
| “No open functional work remains.” | External-app latest-source secure-port closure chain is complete (`RFA-pnxr`, `RFA-ysa5`, `RFA-oo21`, `RFA-t1hb`, `RFA-6mp8`, `RFA-655e` all accepted/closed). | beads issues listed + final latest-source decision artifact |
| CI/security automation gaps listed as unresolved in hardening context | CI push/PR triggers, `security-scan.yml`, and `.github/dependabot.yml` now exist. | `.github/workflows/ci.yaml`, `.github/workflows/security-scan.yml`, `.github/dependabot.yml`, `RFA-l6h6.6.7` evidence |
| `RFA-l6h6.5.1` evidence paths are currently executable from tracked repo state | Historical `RFA-l6h6.5.1` evidence references files removed in commit `ab60428` ("Relocate use-case-specific files to gitignored local directory"); reconciliation is tracked in `RFA-l6h6.6.16`. | `git show --name-status ab60428`, beads issues `RFA-l6h6.5.1`, `RFA-l6h6.6.16` |

---

## 1. Project Summary

PRECINCT implements a **Model Context Protocol (MCP) Security Gateway** that interposes between AI agents and their tools, enforcing a 13-layer security middleware chain. The project validates that the security controls described in the 200+ page reference architecture document are implementable, composable, and operationally viable.

Two deployment targets exist: a Docker Compose stack for local development and validation, and Kubernetes manifests (EKS-targeted) for production-grade deployment.

Core Phase 1 capability gaps (SPIKE Nexus, deep scan, session persistence, mTLS, observability, compliance automation, cosign verification, CLI setup wizard, registry hot-reload) have been addressed, and the production-readiness closure epic (`RFA-l6h6.7`) is accepted and closed.

---

## 2. What Was Built

### 2.1 Metrics

| Metric | Value |
|--------|-------|
| Issues tracked (beads) | 234 total (230 closed, 4 active in documentation epic) |
| Closed epics | 29 |
| Commits on main | ~235 |
| Go source lines | ~16,700 |
| Go test lines | ~43,300 |
| Go test functions | 1,002 |
| OPA Rego lines | ~2,000 (67 policy tests) |
| OpenTofu (HCL) lines | ~29,400 |
| Kubernetes YAML lines | ~28,400 |
| Shell scripts | ~6,500 lines |
| Python (compliance + SDK + agents) | ~6,800 lines |
| E2E demo suites | 2 (Go: 21 tests, Python: 22 tests) |
| K8s NetworkPolicies | 26 across 6 namespaces |

### 2.2 Epics Completed

| Epic | Scope | Stories |
|------|-------|---------|
| RFA-qq0 | Docker Compose POC -- full 13-middleware chain | 18 stories |
| RFA-d13 | Embed OPA as Go library (eliminate sidecar) | 1 story |
| RFA-eu8 | Phase 2 Walking Skeleton -- SPIKE Nexus + OTel E2E vertical slice | 2 stories |
| RFA-9wg | MCP Transport Support -- Streamable HTTP + Legacy SSE | 7 stories |
| RFA-j2d | MCP-UI / Apps Extension security (SEP-1865) | 10 stories |
| RFA-9fv | EKS v2 -- production-grade Kubernetes manifests | 2 stories |
| RFA-a2y | SPIKE Nexus E2E -- late-binding secrets proven | 2 stories |
| RFA-pkm | Deep Scan & Guard Model -- Groq E2E with fallback | 2 stories |
| RFA-7sh | Deep Scan Hardening -- Groq E2E, chunking, and fallback policy | 2 stories |
| RFA-hh5 | Session Persistence & KeyDB -- cross-request detection | 3 stories |
| RFA-8z8 | mTLS Enforcement -- SPIRE SVID-based encryption | 2 stories |
| RFA-m6j | Observability -- OTel spans across all middleware | 3 stories |
| RFA-8jl | Compliance Automation -- one-button 4-framework report | 3 stories |
| RFA-h3c | Compliance Automation (follow-up) -- 4-framework report | 2 stories |
| RFA-28q | CLI Setup Wizard -- guided configuration for non-security-experts | 2 stories |
| RFA-tj9 | CLI Setup & Developer Experience | 6 stories |
| RFA-62b | Agent SDK -- framework-independent gateway client (Go + Python) | 2 stories |
| RFA-62e | Registry Hot-Reload with Attestation | 2 stories |
| RFA-5kv | Production Hardening -- cosign, local K8s validation, pattern audit, CI security | 3 stories |
| RFA-7bh | Local K8s -- full stack on Docker Desktop kubeadm | 2 stories |
| RFA-lo1 | Hardening & CI -- security scanning, benchmarks, pattern audit | 3 stories |
| RFA-ppz | Documentation and DX -- audience-oriented docs, error pages, benchmarks | 2 stories |
| RFA-ev6 | E2E Demo Output Enrichment + prompt injection + secrets/SPIKE tests | 5 stories |
| RFA-oyg | SPIKE Nexus Production Parity -- Pilot Seeder + SQLite backend | 4 stories |
| RFA-eiy | K8s SPIKE Production Parity -- full secret management stack on Docker Desktop K8s | 7 stories |
| RFA-4zz | K8s NetworkPolicy Full Coverage -- default-deny + explicit allow for all namespaces | 5 stories |
| RFA-4m9 | Standalone Persistent Phoenix Observability | 7 stories |
| RFA-a6z | DLP & Guard Model Hardening -- GROQ wiring, configurable guard model, DLP policy | 7 stories |
| RFA-keg | Demo E2E Reliability -- deep scan integration, rate limit, proof collection | 4 stories |
| RFA-50d | SPIKE Nexus Fully Functional in Docker Compose Demo -- token redemption E2E | 1 story |
| RFA-2irf | Documentation Overhaul and AI Skill Creation | in progress |
| Discovery bugs & cleanup | Port conflicts, dead code, protocol methods, KeyDB fixes | ~75 stories |

### 2.3 The 13-Middleware Chain

| Step | Middleware | Status | Notes |
|------|-----------|--------|-------|
| 1 | Request Size Limit | PROVEN | Configurable, default 10MB; OTel span instrumented |
| 2 | Body Capture | PROVEN | Buffers for downstream inspection; OTel span instrumented |
| 3 | SPIFFE Auth | PROVEN | mTLS via SPIRE SVIDs in prod mode; dev mode (header-based) preserved; OTel span |
| 4 | Audit Logging | PROVEN | Hash-chained, async (99.2% latency reduction), OTel span |
| 5 | Tool Registry Verify | PROVEN | SHA-256 hash verification, hot-reload with cosign-blob attestation, OTel span |
| 6 | OPA Policy | PROVEN | Embedded Rego, bundle digest tracking, OTel span |
| 7 | DLP Scan | PROVEN | Credentials blocked (fail-closed), PII flagged (audit-only), injection configurable (block or flag via DLP_INJECTION_POLICY env), OTel span |
| 8 | Session Context | PROVEN | KeyDB-backed persistence, cross-request exfiltration detection, GDPR delete, OTel span |
| 9 | Step-Up Gating | PROVEN | Risk scoring, fast-path for low-risk, OTel span |
| 10 | Deep Scan Dispatch | PROVEN | Configurable guard model (GUARD_MODEL_ENDPOINT, GUARD_MODEL_NAME, GUARD_API_KEY; defaults to Groq Prompt Guard 2), prompt chunking (512-token windows), configurable fail-closed/fail-open, OTel span |
| 11 | Rate Limiting | PROVEN | KeyDB-backed distributed token bucket, X-RateLimit headers, OTel span |
| 12 | Circuit Breaker | PROVEN | closed/open/half-open state tracking, OTel span |
| 13 | Token Substitution | PROVEN | SPIKE Nexus integration via SPIKENexusRedeemer, scope validation via registry, OTel span |

All 13 middleware layers are fully instrumented with OTel spans and tested with real backends.

### 2.4 Infrastructure Services

| Service | Image | Status |
|---------|-------|--------|
| SPIKE Nexus | ghcr.io/spiffe/spike-nexus:0.8.0 | Active in docker-compose.yml, SQLite backend, fully functional token redemption (HTTP 200) |
| SPIKE Pilot (Secret Seeder) | ghcr.io/spiffe/spike:0.8.0 | One-shot init container for secret seeding via official CLI |
| KeyDB | eqalpha/keydb:latest | Active with TLS (SVID certs) |
| SPIRE Server | ghcr.io/spiffe/spire-server:1.10.0 | Active |
| SPIRE Agent | Custom wrapper | Active with Docker attestor |
| OTel Collector | otel/opentelemetry-collector-contrib:latest | Active, receives gateway spans |
| Phoenix | arizephoenix/phoenix:latest | Standalone persistent deployment (docker-compose.phoenix.yml), survives demo teardowns, cross-run trace history |

### 2.5 EKS Infrastructure (Validated Offline)

All manifests validated with `kubeconform --strict`, `kustomize build`, and `tofu validate`. Not yet deployed to a running cluster.

- OpenTofu EKS cluster (VPC, 3 AZs, OIDC, NetworkPolicy CNI)
- SPIRE Server (HA StatefulSet) + Agent (DaemonSet) + SPIKE Nexus
- Gateway deployment with security context (non-root, read-only rootfs)
- MCP server placeholder in tools namespace
- S3 MCP tool server (Go, with bucket/prefix allowlist enforcement)
- NetworkPolicies (26 policies across 6 namespaces: default-deny ingress+egress, explicit allows for all legitimate communication paths)
- OTEL Collector -> Phoenix, audit to S3 with Object Lock COMPLIANCE
- CI/CD: GitHub Actions with cosign OIDC signing, SBOM generation, dev/staging/prod overlays
- Admission control: OPA Gatekeeper + sigstore/policy-controller (cosign signature verification)

### 2.6 MCP-UI Security Controls (Library + Gateway Wiring)

Implements SEP-1865 (Apps Extension) security:

- **Capability Gating**: deny/allow/audit-only per server, strip disallowed tools from tools/list
- **UI Resource Registry**: SHA-256 content hash verification, rug-pull detection
- **UI Resource Controls**: content-type validation, size limits, dangerous pattern scanning, caching
- **CSP Mediation**: intersect server-declared CSP with grant allowlists, hard constraints
- **Permissions Mediation**: filter permissions against grant's allowed_permissions
- **Tool-Call Mediation**: app-driven call origin detection, visibility checks, cross-server blocking
- **OPA Policy Extensions**: UIInput struct, deny_ui_resource, deny_app_tool_call, requires_step_up
- **Audit Extensions**: 10 UI event types, severity classification, EmitUIEvent on Auditor

### 2.7 Compliance Automation

`make compliance-report` generates auditor-ready compliance evidence:

- **Formats**: XLSX (per-control evidence), CSV (machine-parseable), PDF (executive summary)
- **Frameworks**: SOC 2 Type II, ISO 27001, CCPA/CPRA, GDPR
- **Control taxonomy**: 10 control areas mapped to framework requirements
- **Evidence**: audit log entries, policy configurations, test results
- **GDPR Art. 30 ROPA**: Data processing records integrated into report

### 2.8 Developer Experience

- **CLI Setup Wizard** (`make setup` / `scripts/setup.sh`, 737 lines): Guided configuration with prerequisite checks, security posture summary, configurable deep scan fallback policy
- **Go SDK** (`mcp-gateway-sdk-go`): Framework-independent gateway client with structured error handling
- **Python SDK** (`mcp_gateway_sdk`): Unified error parsing and retry logic
- **Unified JSON Error Envelope**: Standardized error responses across all middleware with error codes, remediation hints, and documentation URLs
- **Documentation Suite**: README.md (30-second overview), API reference, Go SDK docs, Python SDK docs, deployment guide (Docker Compose + K8s + Phoenix), configuration reference (all env vars by component)
- **Configurable Guard Model**: GUARD_MODEL_ENDPOINT, GUARD_MODEL_NAME, GUARD_API_KEY env vars allow swapping the deep scan model without code changes
- **DLP Policy Per Category**: Credentials always block (security invariant); injection policy configurable via DLP_INJECTION_POLICY (block or flag); PII flagged for audit

---

## 3. What Was Proven

| Claim | Evidence |
|-------|----------|
| 13-middleware chain composes cleanly in Go | E2E demo suites: Go 21/21, Python 22/22 (Docker Compose and K8s) |
| Tool poisoning detection works | SHA-256 hash mismatch returns 403; 7 OPA regex patterns detect description injection |
| DLP at gateway boundary catches credentials | AWS keys, private keys, passwords blocked fail-closed in E2E |
| Hash-chained audit is tamper-evident | prev_hash links events; bundle_digest and registry_digest prove policy consistency |
| SPIFFE identity enables workload attestation | SPIRE server+agent with Docker attestor; SPIFFE IDs in audit and OPA grants |
| Embedded OPA eliminates sidecar failure mode | Network latency removed; bundle digest proves loaded policy version |
| Session context enables cross-request exfiltration detection | KeyDB-backed persistence; DetectsExfiltrationPattern() across requests |
| EKS IaC is structurally sound | tofu validate, kubeconform, kustomize build all pass for all manifests |
| Supply chain controls compose well | cosign OIDC, syft SBOMs, digest pinning, Gatekeeper admission, promotion gates |
| Library/wiring separation scales | j2d epic: 4 library stories + 1 wiring story; each independently testable |
| Late-binding secrets work E2E | SPIKE Nexus in docker-compose.yml; SPIKENexusRedeemer redeems tokens via mTLS |
| mTLS enforcement via SPIRE SVIDs | Gateway, SPIKE Nexus, KeyDB all use SVID-based TLS in prod mode |
| Per-middleware OTel spans provide full visibility | 13+ child spans per request visible in Phoenix via OTel Collector |
| Deep scan catches prompt injection | Groq Prompt Guard 2 with chunking; configurable fail-closed/fail-open |
| One-button compliance evidence generation | `make compliance-report` produces XLSX/CSV/PDF for 4 frameworks |
| Registry hot-reload with attestation | fsnotify watcher with cosign-blob Ed25519 signature verification |
| Async audit logging preserves correctness | Hash chain under mutex (~2-3us), file I/O async via 4096-event buffered channel |
| Guard model is configurable | GUARD_MODEL_ENDPOINT, GUARD_MODEL_NAME, GUARD_API_KEY env vars; defaults to Groq Prompt Guard 2 |
| DLP policy per category is configurable | Credentials always block (security invariant), injection block or flag (DLP_INJECTION_POLICY), PII flag |
| SPIKE Nexus token redemption works E2E | Token substitution returns HTTP 200 with redeemed secret; spike-secret-seeder init container; devMode OwnerID |
| SPIKE SQLite persistence works | SPIKE Nexus with SQLite backend survives container restarts; secrets persist |
| K8s NetworkPolicy full coverage | 26 NetworkPolicies across 6 namespaces (gateway, tools, data, spike-system, spire-system, observability); default-deny ingress+egress |
| Standalone Phoenix survives demo teardowns | docker-compose.phoenix.yml runs independently; both Docker Compose and K8s demos send traces to single persistent instance |
| K8s SPIKE production parity | Full secret management stack on Docker Desktop kubeadm: Nexus, Pilot, SPIRE entries, gateway env injection |
| MCP Streamable HTTP transport | Streamable HTTP + legacy SSE support; transport-agnostic middleware chain |
| Demo E2E reliability under real conditions | Injection tests accept deep scan outcomes; rate limit with demo params (RPM=60, BURST=10); context propagation for proof collection |

---

## 4. Current Status

All Phase 1 functional gaps have been addressed. Production-readiness closure epic `RFA-l6h6.7` is accepted/closed, external-app full-port execution story `RFA-l6h6.6.10` is accepted/closed, and framework-gap closure reassessment (`RFA-l6h6.6.17.1`) is accepted/closed with a GO decision for advancing beyond the framework-closure gate.

### 4.1 Rego Cannot Do Cryptographic Signature Verification

OPA Gatekeeper ConstraintTemplates enforce digest pinning and registry allowlists, but actual cosign signature verification requires sigstore/policy-controller webhook. Both run as K8s admission webhooks and are complementary.

**Status:** Both implemented. Rego does prerequisite checks; sigstore/policy-controller does crypto verification.

### 4.2 SPIKE Nexus Maturity

SPIKE is at "Development" maturity (not production-ready per SPIFFE lifecycle). Acceptable for a reference implementation. Keepers (Tier 4, Shamir key sharding) would be needed for production HA.

### 4.3 EKS Not Deployed to Running Cluster

All EKS manifests are validated offline. Cloud deployment requires an AWS account and is an infrastructure concern, not a security validation gap.

### 4.4 Python Agents Not in Compose

DSPy, PydanticAI, and other Python agent frameworks run externally and connect to the gateway. This is by design -- the gateway is agent-framework agnostic.

---

## 5. Architecture Decisions Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Go for gateway | Performance, static typing, single binary, strong concurrency | 2026-02-05 |
| Embedded OPA (no sidecar) | Eliminates network latency and failure domain | 2026-02-05 |
| OpenTofu over Terraform | MPL-2.0 licensing for reference architecture forkability | 2026-02-05 |
| SPIRE for identity (no cert-manager) | CNCF-standard, single CA, no confused-deputy risk | 2026-02-05 |
| KeyDB over Redis | BSD-3-Clause licensing removes enterprise adoption ambiguity | 2026-02-06 |
| OpenBAO over Vault (K8s Tier 2) | MPL-2.0 licensing, API-compatible | 2026-02-06 |
| Library/wiring separation | Component stories testable independently; wiring story integrates | 2026-02-05 |
| Token substitution as innermost middleware | Security invariant: secrets must never be visible to any other middleware | 2026-02-05 |
| DLP: credentials fail-closed, PII audit-only | Different risk profiles warrant different enforcement modes | 2026-02-05 |
| Hash-chained audit (async) | Tamper-evident log; hash chain synchronous, I/O async | 2026-02-06 |
| Cosign verification K8s-only | Docker Compose builds from source; supply chain IS the source code | 2026-02-06 |
| Deep scan fail-closed/fail-open at setup time | Informed consent; users choose security posture explicitly | 2026-02-06 |
| Compliance reports in Python | openpyxl/fpdf2 maturity; offline tool, zero coupling to Go gateway | 2026-02-06 |
| Registry hot-reload with cosign-blob attestation | Operational agility with mandatory signature verification | 2026-02-06 |
| SPIKE Pilot for secret seeding (not custom binary) | Official CLI is maintained upstream; reduces custom code surface | 2026-02-07 |
| SPIKE SQLite backend for persistence | Secrets survive container restarts; memory-mode insufficient for demo reliability | 2026-02-07 |
| Standalone Phoenix deployment | Traces persist across demo teardowns; single instance serves both Compose and K8s | 2026-02-07 |
| Configurable guard model via env vars | Enables swapping deep scan model (e.g., local vs cloud) without code changes | 2026-02-08 |
| DLP injection policy as flag vs block | Credentials always block (security invariant); injection policy varies by use case | 2026-02-08 |
| K8s NetworkPolicy default-deny everywhere | Zero-trust network posture; explicit allows for every legitimate path | 2026-02-07 |
| Context propagation via SecurityFlagsCollector | Mutable struct shared via pointer in Go context; allows downstream middleware to populate upstream audit fields | 2026-02-08 |

---

## 6. Roadmap: Future Work

### 6.1 P1 -- Operational Validation

| Item | Description | Status |
|------|-------------|--------|
| Docker Desktop K8s | Full stack on Docker Desktop kubeadm with local overlay | Done (RFA-7bh, RFA-eiy) |
| EKS cloud deployment | Deploy to real EKS cluster with production workloads | Not started |
| E2E with real Groq API | Deep scan with real Groq Prompt Guard 2 API calls | Done (RFA-pkm, RFA-a6z) |
| E2E with real external MCP servers | Test full flow with third-party MCP servers | Not started |
| Load testing | Benchmark combined stack (SPIKE Nexus + KeyDB + OTel) under realistic load | Not started |

### 6.2 P2 -- Extensions

| Item | Description |
|------|-------------|
| Multi-agent orchestration | Agent-to-agent communication through gateway, SPIFFE grant models |
| Streaming MCP support | Progressive inspection for chunked/streaming responses |
| T5-small fine-tuning | Offline deep scan fallback via DSPy (research-grade) |
| SPIKE Keepers (HA) | Shamir key sharding for production secret management |
| Optional LLMTrace prompt-injection backend | Exploration-only option for customer environments that reject Groq in hot path; detector backend only, with gateway as enforcement authority and Arize/Phoenix retained for observability (`docs/architecture/llmtrace-prompt-injection-exploration-option.md`) |

### 6.3 P3 -- Strategic

| Item | Description |
|------|-------------|
| Plugin ecosystem | Marketplace for tool providers with automated security review |
| Compliance reporting UI | Dashboard for audit trail visualization |
| Model supply chain | SLSA provenance attestations, reproducible builds |

---

## 7. How to Reproduce

```bash
# Docker Compose stack
cd POC
make setup                           # Interactive setup wizard
make up                              # Start all services
make demo-compose                    # Run full E2E demo (Go 21 + Python 22 tests)

# K8s local stack (Docker Desktop kubeadm)
make k8s-local-up                    # Start K8s local overlay
make demo-k8s                        # Run full E2E demo on K8s

# Phoenix observability (standalone, persistent)
make phoenix-up                      # Start standalone Phoenix + OTel Collector
make phoenix-down                    # Stop Phoenix (traces persist)

# Individual E2E scenarios (legacy shell-based)
bash tests/e2e/scenario_a_happy_path.sh
bash tests/e2e/scenario_b_security_denial.sh
bash tests/e2e/scenario_c_exfiltration.sh
bash tests/e2e/scenario_d_tool_poisoning.sh
bash tests/e2e/scenario_e_dlp.sh
bash tests/e2e/scenario_spike_nexus.sh
bash tests/e2e/readiness_checklist.sh
bash tests/e2e/middleware_chain_verify.sh

# Go tests
go test ./internal/gateway/... ./internal/gateway/middleware/...

# OPA policy tests
opa test config/opa/ --v0-compatible -v

# Compliance report
make compliance-report               # Generates XLSX/CSV/PDF in reports/

# Readiness state integrity (doc-state drift check against bd)
make readiness-state-validate

# GDPR right-to-deletion
make gdpr-delete SPIFFE_ID=spiffe://poc.local/agent/example

# EKS manifest validation (offline)
cd infra/eks && tofu validate
kubeconform --strict infra/eks/**/*.yaml
kustomize build infra/eks/overlays/dev
```
