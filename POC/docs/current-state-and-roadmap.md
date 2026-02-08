# Current State and Roadmap

**Last Updated:** 2026-02-07
**Branch:** main (merged from epic/RFA-qq0-poc-docker-compose)
**Reference Architecture Version:** 2.2

---

## 1. Project Summary

The Agentic AI Security Reference Architecture POC implements a **Model Context Protocol (MCP) Security Gateway** that interposes between AI agents and their tools, enforcing a 13-layer security middleware chain. The project validates that the security controls described in the 200+ page reference architecture document are implementable, composable, and operationally viable.

Two deployment targets exist: a Docker Compose stack for local development and validation, and Kubernetes manifests (EKS-targeted) for production-grade deployment.

All identified Phase 1 gaps (SPIKE Nexus, deep scan, session persistence, mTLS, observability, compliance automation, cosign verification, CLI setup wizard, registry hot-reload) have been addressed. The project is development-complete.

---

## 2. What Was Built

### 2.1 Metrics

| Metric | Value |
|--------|-------|
| Issues tracked (beads) | 158 (all closed) |
| Commits on main | 143 |
| Go source lines | ~13,400 |
| Go test lines | ~28,300 |
| Test functions | 675 |
| OPA Rego lines | ~1,200 (67 policy tests) |
| OpenTofu (HCL) lines | ~29,000 |
| Kubernetes YAML lines | ~24,000 |
| Shell scripts | ~3,400 lines |
| Python (compliance + setup) | ~2,000 lines |
| E2E test suites | 7 (65 PASS / 0 FAIL / 1 SKIP) |

### 2.2 Epics Completed

| Epic | Scope | Stories |
|------|-------|---------|
| RFA-qq0 | Docker Compose POC -- full 13-middleware chain | 28 stories |
| RFA-d13 | Embed OPA as Go library (eliminate sidecar) | 1 story |
| RFA-j2d | MCP-UI / Apps Extension security (SEP-1865) | 9 stories |
| RFA-9fv | EKS v2 -- production-grade Kubernetes manifests | 9 stories |
| RFA-a2y | SPIKE Nexus E2E -- late-binding secrets proven | 2 stories |
| RFA-pkm | Deep Scan & Guard Model -- Groq E2E with fallback | 2 stories |
| RFA-hh5 | Session Persistence & KeyDB -- cross-request detection | 3 stories |
| RFA-8z8 | mTLS Enforcement -- SPIRE SVID-based encryption | 2 stories |
| RFA-m6j | Observability -- OTel spans across all middleware | 3 stories |
| RFA-8jl | Compliance Automation -- one-button 4-framework report | 3 stories |
| RFA-tj9 | CLI Setup & Developer Experience | 3 stories |
| RFA-62e | Registry Hot-Reload with Attestation | 4 stories |
| RFA-7bh | Production Hardening -- cosign, K8s validation, pattern audit | 2 stories |
| RFA-lo1 | CI/CD Security & Performance Benchmarking | 4 stories |
| Discovery bugs & cleanup | Port conflicts, dead code, protocol methods, KeyDB fixes | ~40+ stories |

### 2.3 The 13-Middleware Chain

| Step | Middleware | Status | Notes |
|------|-----------|--------|-------|
| 1 | Request Size Limit | PROVEN | Configurable, default 10MB; OTel span instrumented |
| 2 | Body Capture | PROVEN | Buffers for downstream inspection; OTel span instrumented |
| 3 | SPIFFE Auth | PROVEN | mTLS via SPIRE SVIDs in prod mode; dev mode (header-based) preserved; OTel span |
| 4 | Audit Logging | PROVEN | Hash-chained, async (99.2% latency reduction), OTel span |
| 5 | Tool Registry Verify | PROVEN | SHA-256 hash verification, hot-reload with cosign-blob attestation, OTel span |
| 6 | OPA Policy | PROVEN | Embedded Rego, bundle digest tracking, OTel span |
| 7 | DLP Scan | PROVEN | Credentials blocked (fail-closed), PII flagged (audit-only), OTel span |
| 8 | Session Context | PROVEN | KeyDB-backed persistence, cross-request exfiltration detection, GDPR delete, OTel span |
| 9 | Step-Up Gating | PROVEN | Risk scoring, fast-path for low-risk, OTel span |
| 10 | Deep Scan Dispatch | PROVEN | Groq Prompt Guard 2, prompt chunking (512-token windows), configurable fail-closed/fail-open, OTel span |
| 11 | Rate Limiting | PROVEN | KeyDB-backed distributed token bucket, X-RateLimit headers, OTel span |
| 12 | Circuit Breaker | PROVEN | closed/open/half-open state tracking, OTel span |
| 13 | Token Substitution | PROVEN | SPIKE Nexus integration via SPIKENexusRedeemer, scope validation via registry, OTel span |

All 13 middleware layers are fully instrumented with OTel spans and tested with real backends.

### 2.4 Infrastructure Services

| Service | Image | Status |
|---------|-------|--------|
| SPIKE Nexus | ghcr.io/spiffe/spike-nexus:0.8.0 | Active in docker-compose.yml |
| SPIKE Bootstrap | ghcr.io/spiffe/spike-nexus:0.8.0 | One-shot init for root key |
| KeyDB | eqalpha/keydb:latest | Active with TLS (SVID certs) |
| SPIRE Server | ghcr.io/spiffe/spire-server:1.10.0 | Active |
| SPIRE Agent | Custom wrapper | Active with Docker attestor |
| OTel Collector | otel/opentelemetry-collector-contrib:latest | Active, receives gateway spans |
| Phoenix | arizephoenix/phoenix:latest | Active, displays trace waterfall |

### 2.5 EKS Infrastructure (Validated Offline)

All manifests validated with `kubeconform --strict`, `kustomize build`, and `tofu validate`. Not yet deployed to a running cluster.

- OpenTofu EKS cluster (VPC, 3 AZs, OIDC, NetworkPolicy CNI)
- SPIRE Server (HA StatefulSet) + Agent (DaemonSet) + SPIKE Nexus
- Gateway deployment with security context (non-root, read-only rootfs)
- MCP server placeholder in tools namespace
- S3 MCP tool server (Go, with bucket/prefix allowlist enforcement)
- NetworkPolicies (default-deny ingress+egress, explicit allows)
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

---

## 3. What Was Proven

| Claim | Evidence |
|-------|----------|
| 13-middleware chain composes cleanly in Go | E2E suite: 65/66 checks pass across 7 test suites |
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

---

## 4. Known Limitations

### 4.1 Rego Cannot Do Cryptographic Signature Verification

OPA Gatekeeper ConstraintTemplates enforce digest pinning and registry allowlists, but actual cosign signature verification requires sigstore/policy-controller webhook. Both run as K8s admission webhooks and are complementary.

**Status:** Both implemented. Rego does prerequisite checks; sigstore/policy-controller does crypto verification.

### 4.2 SPIKE Nexus Maturity

SPIKE is at "Development" maturity (not production-ready per SPIFFE lifecycle). Acceptable for a reference architecture POC. Keepers (Tier 4, Shamir key sharding) would be needed for production HA.

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

---

## 6. Roadmap: Future Work

### 6.1 P1 -- Operational Validation

| Item | Description | Status |
|------|-------------|--------|
| Deploy to running K8s cluster | Validate Docker Desktop kubeadm or EKS with real workloads | Not started |
| E2E with real external APIs | Test full flow with real Groq API, real external MCP servers | Not started |
| Load testing | Benchmark combined stack (SPIKE Nexus + KeyDB + OTel) under realistic load | Not started |

### 6.2 P2 -- Extensions

| Item | Description |
|------|-------------|
| Multi-agent orchestration | Agent-to-agent communication through gateway, SPIFFE grant models |
| Streaming MCP support | Progressive inspection for chunked/streaming responses |
| T5-small fine-tuning | Offline deep scan fallback via DSPy (research-grade) |
| SPIKE Keepers (HA) | Shamir key sharding for production secret management |

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
bash tests/e2e/run_all.sh           # Run full E2E validation (65 PASS / 0 FAIL / 1 SKIP)

# Individual scenarios
bash tests/e2e/scenario_a_happy_path.sh
bash tests/e2e/scenario_b_security_denial.sh
bash tests/e2e/scenario_c_exfiltration.sh
bash tests/e2e/scenario_d_tool_poisoning.sh
bash tests/e2e/scenario_e_dlp.sh
bash tests/e2e/readiness_checklist.sh
bash tests/e2e/middleware_chain_verify.sh

# Go tests
go test ./internal/gateway/... ./internal/gateway/middleware/...

# OPA policy tests
opa test config/opa/ --v0-compatible -v

# Compliance report
make compliance-report               # Generates XLSX/CSV/PDF in reports/

# GDPR right-to-deletion
make gdpr-delete SPIFFE_ID=spiffe://poc.local/agent/example

# EKS manifest validation (offline)
cd infra/eks && tofu validate
kubeconform --strict infra/eks/**/*.yaml
kustomize build infra/eks/overlays/dev
```
