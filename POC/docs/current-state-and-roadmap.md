# Current State and Roadmap

**Last Updated:** 2026-02-06
**Branch:** epic/RFA-qq0-poc-docker-compose
**Reference Architecture Version:** 2.2

---

## 1. Project Summary

The Agentic AI Security Reference Architecture POC implements a **Model Context Protocol (MCP) Security Gateway** that interposes between AI agents and their tools, enforcing a 13-layer security middleware chain. The project validates that the security controls described in the 200+ page reference architecture document are implementable, composable, and operationally viable.

Two deployment targets exist: a Docker Compose stack for local development and validation, and Kubernetes manifests (EKS-targeted) for production-grade deployment.

---

## 2. What Was Built

### 2.1 Metrics

| Metric | Value |
|--------|-------|
| Issues tracked (beads) | 70 (all closed) |
| Commits on epic branch | ~75 |
| Go source lines | ~35,000 |
| Go test lines | ~25,000 |
| Test functions | 594 |
| OPA Rego lines | ~1,200 (67 policy tests) |
| OpenTofu (HCL) lines | ~29,000 |
| Kubernetes YAML lines | ~24,000 |
| Shell scripts | ~3,400 lines |
| E2E test suites | 7 (65 PASS / 0 FAIL / 1 SKIP) |

### 2.2 Epics Completed

| Epic | Scope | Stories |
|------|-------|---------|
| RFA-qq0 | Docker Compose POC -- full 13-middleware chain | 28 stories |
| RFA-d13 | Embed OPA as Go library (eliminate sidecar) | 1 story |
| RFA-j2d | MCP-UI / Apps Extension security (SEP-1865) | 9 stories |
| RFA-9fv | EKS v2 -- production-grade Kubernetes manifests | 9 stories |
| Discovery bugs & cleanup | Port conflicts, dead code, protocol methods | ~23 stories |

### 2.3 The 13-Middleware Chain

| Step | Middleware | Status | Notes |
|------|-----------|--------|-------|
| 1 | Request Size Limit | PROVEN | Configurable, default 10MB |
| 2 | Body Capture | PROVEN | Buffers for downstream inspection |
| 3 | SPIFFE Auth | PROVEN | Dev mode (header-based); mTLS ready but not enforced |
| 4 | Audit Logging | PROVEN | Hash-chained with session_id, decision_id, trace_id |
| 5 | Tool Registry Verify | PROVEN | SHA-256 hash mismatch detection, 403 blocking |
| 6 | OPA Policy | PROVEN | Embedded Rego, bundle digest tracking |
| 7 | DLP Scan | PROVEN | Credentials blocked (fail-closed), PII flagged (audit-only) |
| 8 | Session Context | PROVEN | Per-session history, exfiltration detection logic works |
| 9 | Step-Up Gating | PROVEN | Risk scoring, fast-path for low-risk |
| 10 | Deep Scan Dispatch | PARTIAL | Async dispatch works; no-op without GROQ_API_KEY |
| 11 | Rate Limiting | PROVEN | Per-agent token bucket, X-RateLimit headers |
| 12 | Circuit Breaker | PROVEN | closed/open/half-open state tracking |
| 13 | Token Substitution | PROVEN | $SPIKE{ref:} format works; no real SPIKE Nexus backend |

### 2.4 EKS Infrastructure (Validated Offline)

All manifests validated with `kubeconform --strict`, `kustomize build`, and `tofu validate`. Not yet deployed to a running cluster.

- OpenTofu EKS cluster (VPC, 3 AZs, OIDC, NetworkPolicy CNI)
- SPIRE Server (HA StatefulSet) + Agent (DaemonSet) + SPIKE Nexus
- Gateway deployment with security context (non-root, read-only rootfs)
- MCP server placeholder in tools namespace
- S3 MCP tool server (Go, with bucket/prefix allowlist enforcement)
- NetworkPolicies (default-deny ingress+egress, explicit allows)
- OTEL Collector -> Phoenix, audit to S3 with Object Lock COMPLIANCE
- CI/CD: GitHub Actions with cosign OIDC signing, SBOM generation, dev/staging/prod overlays
- Admission control: OPA Gatekeeper ConstraintTemplates (digest pinning, registry allowlist)

### 2.5 MCP-UI Security Controls (Library + Gateway Wiring)

Implements SEP-1865 (Apps Extension) security:

- **Capability Gating**: deny/allow/audit-only per server, strip disallowed tools from tools/list
- **UI Resource Registry**: SHA-256 content hash verification, rug-pull detection
- **UI Resource Controls**: content-type validation, size limits, dangerous pattern scanning, caching
- **CSP Mediation**: intersect server-declared CSP with grant allowlists, hard constraints
- **Permissions Mediation**: filter permissions against grant's allowed_permissions
- **Tool-Call Mediation**: app-driven call origin detection, visibility checks, cross-server blocking
- **OPA Policy Extensions**: UIInput struct, deny_ui_resource, deny_app_tool_call, requires_step_up
- **Audit Extensions**: 10 UI event types, severity classification, EmitUIEvent on Auditor

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
| Session context enables exfiltration detection | DetectsExfiltrationPattern() verified in unit tests (sensitive read + external target) |
| EKS IaC is structurally sound | tofu validate, kubeconform, kustomize build all pass for all manifests |
| Supply chain controls compose well | cosign OIDC, syft SBOMs, digest pinning, Gatekeeper admission, promotion gates |
| Library/wiring separation scales | j2d epic: 4 library stories + 1 wiring story; each independently testable |

---

## 4. What Was Disproven or Found Insufficient

### 4.1 SPIKE Nexus Not Tested at Runtime (P0 GAP)

**Status:** SPIKE Nexus is commented out of docker-compose.yml. Token substitution middleware exists and handles `$SPIKE{ref:path}` patterns, but was only tested with mocked backends. This is the architecture's most innovative component -- the zero-trust secrets gateway that prevents agents from ever seeing raw credentials -- and it must be fully operational.

**Impact:** The core value proposition of "agents never touch secrets" is unverified end-to-end.

**Required:** Uncomment SPIKE Nexus, configure token issuance, test real secret substitution through the full stack.

### 4.2 Cross-Request Exfiltration Requires Sticky Sessions

The detection logic works within a single session, but without session persistence (X-Session-ID header or infrastructure stickiness), each HTTP request creates a new session. An attacker could read secrets in request 1 and exfiltrate in request 2 without detection.

**Status:** Detection logic correct; session persistence is an infrastructure gap.

### 4.3 Deep Scan Is a No-Op Without LLM Backend

Without GROQ_API_KEY, the deep scan middleware dispatches asynchronously but does nothing. The GROQ_API_KEY exists in `.env` but has not been tested end-to-end. The architecture calls for a guard model (Prompt Guard 2 via Groq) but has no fallback chain if the model is unavailable, rate-limited, or insufficient.

**Status:** Middleware wired; LLM chain not configured or documented.

### 4.4 Rego Cannot Do Cryptographic Signature Verification

OPA Gatekeeper ConstraintTemplates enforce digest pinning and registry allowlists, but actual cosign signature verification requires sigstore/policy-controller webhook. The Rego policy is a prerequisite check, not a complete solution.

**Status:** Prerequisite implemented; cryptographic verification needs external controller.

### 4.5 mTLS Not Enforced

SPIRE infrastructure is deployed and workload entries exist, but containers communicate in dev mode (X-SPIFFE-ID header injection). Real mTLS requires certificate exchange between services.

### 4.6 Observability Gap

Gateway emits structured JSON audit logs but not OTel spans. Phoenix is running but has zero traces. The OTEL Collector is configured but receives no data from the gateway.

### 4.7 No Hot-Reload for Registries

OPA bundles can be hot-reloaded, but the tool registry and UI resource registry are loaded at startup. Production updates require gateway restarts. Externalizing registries introduces a new attack surface (registry poisoning) that must be addressed.

---

## 5. Open Questions Requiring BLT Discussion

### 5.1 Docker Compose vs Kubernetes Patterns

The threat model is virtually the same, but some patterns are deployment-target specific. Need to determine:
- Which controls make sense in Docker Compose (development/single-machine) vs Kubernetes only (production)?
- Should Docker Compose have all controls active for parity, or is a reduced set acceptable for development?
- NetworkPolicies, admission control, and pod security are K8s-native. What are the Docker equivalents?

### 5.2 Local Kubernetes Testing

Docker Desktop is configured as a kubeadm-based K8s endpoint. All EKS manifests should be tested locally before cloud deployment. Need to determine:
- Which manifests need modification for local K8s (no ALB, no IRSA, no EBS CSI)?
- Should we maintain a separate Kustomize overlay for local K8s?
- What is the testing strategy for local K8s vs EKS?

### 5.3 KeyDB vs Redis

KeyDB (`eqalpha/keydb:latest`) chosen for truly open licensing. Need to determine:
- Where does KeyDB fit? Session persistence, distributed rate limiting, both?
- Should it run in Docker Compose for local development too, or only K8s?
- What is the data model for session context in KeyDB?

### 5.4 Cosign Signature Verification

sigstore/policy-controller webhook needed for real signature verification. Need to determine:
- Is this Docker-applicable (via admission webhooks) or K8s-only?
- What is the deployment model (sidecar, standalone, webhook)?
- How does this interact with the existing OPA Gatekeeper admission control?

### 5.5 Deep Scan LLM Chain

Current deep scan has no fallback. Options:
- GROQ_API_KEY exists in `.env` and should be configured immediately
- Train T5-small via DSPy for offline/fallback guard model (see: https://lightning.ai/lightning-ai/environments/dspy-finetune-a-t5-small-to-excel-at-rag)
- Allow user-configurable model chain with explicit fallback behavior
- Prompt chunking may be needed for large payloads (check Groq documentation)

### 5.6 Registry Hot-Reload and Attestation

Hot-reloading tool/UI registries improves operational agility but creates an attack vector:
- Externalized registries become targets for poisoning
- Registry updates need attestation (who signed the update? what changed?)
- Need to balance operational convenience vs security guarantees
- OPA bundle signing model could be extended to registries

### 5.7 mTLS and Certificate Management

Options: manual SPIRE SVIDs, cert-manager, or hybrid. Need to determine:
- cert-manager vs SPIRE-native certificate exchange?
- What is the certificate rotation strategy?
- How does mTLS interact with the existing dev-mode header injection?

---

## 6. Roadmap: Next Phase

### 6.1 P0 -- Immediate (Blocking)

| Item | Description | Target |
|------|-------------|--------|
| SPIKE Nexus activation | Uncomment from compose, configure token issuance, test real secret substitution E2E | Docker Compose |
| Deep scan LLM configuration | Configure GROQ_API_KEY, test Prompt Guard 2 E2E, document prompt chunking | Docker Compose |

### 6.2 P1 -- High Priority

| Item | Description | Target |
|------|-------------|--------|
| Compliance automation | Generate SOC2/ISO27001 evidence from hash-chained audit trail | Both |
| Observability fix | Gateway emits OTel spans to OTEL Collector -> Phoenix | Docker Compose, K8s |
| Session persistence (KeyDB) | Cross-request exfiltration detection, distributed rate limiting | Docker Compose + K8s |
| mTLS enforcement | Real SPIRE SVID-based mTLS between services | Both |
| Local K8s testing | Validate all manifests on Docker Desktop kubeadm K8s | K8s |
| Cosign signature verification | sigstore/policy-controller webhook for admission control | K8s (discuss Docker) |
| Deep scan LLM chain | Fallback chain: Groq -> T5-small (local) -> configurable; DSPy fine-tuning workstream | Both |

### 6.3 P2 -- Important

| Item | Description | Target |
|------|-------------|--------|
| Docker vs K8s pattern audit | Determine which controls are deployment-specific vs universal | Both |
| Registry hot-reload | Watch-based reloading with attestation for tool/UI registries | Both |
| Multi-agent orchestration | Agent-to-agent communication through gateway, SPIFFE grant models | Both |
| SDK / boilerplate reduction | Framework-independent wrapper for agent-gateway integration | Both |
| Skill download and analysis | Integrate or borrow from skulto project for skill security scanning | Both |
| Performance benchmarking | Load testing of 13-middleware chain under realistic agentic workloads | Both |

### 6.4 P3 -- Strategic / Exploratory

| Item | Description | Target |
|------|-------------|--------|
| Plugin ecosystem | Marketplace for tool providers with automated security review | K8s |
| Compliance reporting UI | Dashboard for audit trail visualization and compliance evidence | Both |
| Model supply chain | SLSA provenance attestations, reproducible builds for gateway | K8s |
| Streaming MCP support | Progressive inspection for chunked/streaming responses | Both |

---

## 7. Known Bugs and Technical Debt

| ID | Description | Severity | Status |
|----|-------------|----------|--------|
| RFA-3ii | OTel Collector startup race condition with Phoenix | P3 | Fixed |
| RFA-3xx | OTel Collector deprecated `otlp` alias | P3 | Fixed |
| -- | Gateway emits JSON logs, not OTel spans | P1 | Open |
| -- | Session context in-memory only (no cross-request detection) | P1 | Open |
| -- | SPIKE Nexus commented out of compose | P0 | Open |
| -- | Deep scan is no-op without API key | P1 | Open |
| -- | mTLS dev mode (header injection) | P2 | Open |
| -- | Tool/UI registries loaded at startup only | P2 | Open |
| -- | Python agents (DSPy, PydanticAI) not in compose | P3 | By design (run externally) |

---

## 8. Architecture Decisions Log

| Decision | Rationale | Date |
|----------|-----------|------|
| Go for gateway | Performance, static typing, single binary, strong concurrency | 2026-02-05 |
| Embedded OPA (no sidecar) | Eliminates network latency and failure domain | 2026-02-05 |
| OpenTofu over Terraform | MPL-2.0 licensing for reference architecture forkability | 2026-02-05 |
| SPIRE for identity | CNCF-standard SPIFFE implementation, Docker+K8s attestors | 2026-02-05 |
| KeyDB over Redis | Truly open licensing (eqalpha/keydb:latest) | 2026-02-06 |
| Library/wiring separation | Component stories testable independently; wiring story integrates | 2026-02-05 |
| Token substitution as innermost middleware | Security invariant: secrets must never be visible to any other middleware | 2026-02-05 |
| DLP: credentials fail-closed, PII audit-only | Different risk profiles warrant different enforcement modes | 2026-02-05 |
| Hash-chained audit | Tamper-evident log without external dependency (no blockchain needed) | 2026-02-05 |

---

## 9. How to Reproduce

```bash
# Docker Compose stack
cd POC
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

# EKS manifest validation (offline)
cd infra/eks && tofu validate
kubeconform --strict infra/eks/**/*.yaml
kustomize build infra/eks/overlays/dev
```
