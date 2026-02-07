# BUSINESS.md -- Phase 2: Agentic AI Security Reference Architecture POC

**Version:** 1.0
**Date:** 2026-02-06
**Author:** Business Analyst (D&F Phase)
**Status:** Validated with Business Owner

---

## 1. Business Context

Phase 1 delivered a Docker Compose POC with a 13-middleware MCP Security Gateway (70 stories, all closed). It proved that the security controls described in the 200+ page reference architecture are implementable, composable, and operationally viable.

Phase 2 addresses gaps found during Phase 1, hardens the architecture for production evaluation, and expands to meet the needs of three distinct audiences. The core thesis remains: **agents must never see raw credentials, all tool interactions must be inspected, and the audit trail must be tamper-evident and compliance-ready.**

---

## 2. Target Audiences

| Audience | What They Need | How They Evaluate |
|----------|---------------|-------------------|
| **OSS community / researchers** | Reference security patterns for agentic AI, runnable examples, clear documentation | Git clone, run locally, read code, extend |
| **Enterprise platform / security teams** | Proof that MCP deployments can be secured, architecture they can adapt | Docker Compose evaluation, K8s deployment, threat model review |
| **Regulated industries** (financial services, healthcare, government) | Compliance evidence, auditor-ready reports, encryption of all internal traffic | Compliance report output, control mapping, audit trail integrity |

**Explicitly NOT primary audience (Phase 2):** Tool/MCP server vendors seeking certification or compatibility testing.

---

## 3. Business Outcomes (Success Criteria)

Phase 2 is successful when ALL of the following are demonstrably true:

### O1: Git Clone to Running in Under 30 Minutes

A new user can clone the repository and have the full security stack operational in under 30 minutes, for BOTH Docker Compose and local Kubernetes (Docker Desktop). This time does NOT include container image pulls (network-dependent) but DOES include build, configuration, and startup.

**Measurable:** Timed from `git clone` to first successful E2E request through the full middleware chain.

**Applies to:** Both Docker Compose and local K8s (Docker Desktop kubeadm).

### O2: SPIKE Nexus Proven End-to-End with Real Secrets

The late-binding secrets pattern -- the architecture's most innovative component -- is fully operational and tested with real secret storage and substitution. Agents demonstrably never see raw credentials.

**Measurable:** E2E test where an agent requests a tool call, the gateway substitutes a `$SPIKE{ref:...}` token for the real secret, and the agent's audit trail shows only the opaque token.

**Progression (in priority order):**
1. SPIKE Nexus in Docker Compose with local encrypted storage via CLI
2. SPIKE Nexus backed by OpenBAO (open-source Vault fork) for K8s
3. SPIKE Nexus with Keeper(s) for HA via Shamir key sharding

**Scope:** Operational in BOTH Docker Compose and local K8s.

### O3: One-Button Compliance Evidence Generation

An evaluator can run a single command and receive auditor-ready compliance evidence mapped to four frameworks.

**Frameworks (all table stakes):**
- SOC 2 Type II
- ISO 27001
- CCPA/CPRA
- GDPR

**Output format:** Standalone XLSX/CSV/PDF. NOT vendor-specific (not Vanta API format, not Drata format). Must be consumable by any compliance tool or human auditor.

**Scope:** Gateway-enforced controls only (authentication, authorization, DLP, audit, secrets management, session tracking, content scanning). Infrastructure hardening (K8s node security, network segmentation, cloud IAM) is documented as recommendations, not automated.

**Measurable:** Running `make compliance-report` (or equivalent) produces a report mapping each control to framework requirements with evidence references (audit log entries, policy configurations, test results).

### O4: Full Observability (No Empty Dashboards)

The gateway emits OpenTelemetry spans that provide visibility into every request through the middleware chain.

**Requirements:**
- Per-middleware-layer spans (13 spans per request through the chain)
- Cross-service trace correlation (agent -> gateway -> MCP server -> SPIKE Nexus)
- Standard OTel export (no vendor lock-in; Phoenix is current backend but user may change)

**Measurable:** After a request flows through the gateway, traces are visible in the OTel backend with full middleware chain timing and cross-service correlation.

### O5: Cross-Request Security (Session Persistence)

Exfiltration detection works across HTTP requests, not just within a single request. An attacker cannot read secrets in request 1 and exfiltrate in request 2 without detection.

**Implementation:** KeyDB (eqalpha/keydb:6.3.4, BSD-3-Clause licensed) for session context persistence AND distributed rate limiting.

**Scope:** Both Docker Compose and K8s.

**GDPR/CCPA requirement:** Session data handling must be compliant -- documented retention policy, right-to-deletion mechanism, data processing records.

### O6: Encrypted Internal Communications (mTLS)

All inter-service communication is encrypted via mTLS using SPIFFE SVIDs. No service communicates over plaintext HTTP, including in Docker Compose.

**Scope:** All services (agent <-> gateway <-> MCP server <-> SPIKE Nexus). Not limited to the trust boundary.

**Measurable:** Wireshark/tcpdump on internal Docker/K8s network shows only TLS traffic.

### O7: Clean Setup Experience for Non-Security-Experts

New users who "don't know much about security" can set up the system through a CLI-based guided setup. The setup explicitly informs users of security posture decisions (e.g., deep scan configuration, fail-open vs fail-closed choices).

**Measurable:** A user who has never seen the repo can follow the CLI prompts and have a working, correctly-configured stack without reading the 200-page reference architecture.

---

## 4. Priority Classification

### P0 -- Blocking (Must Complete First)

| ID | Item | Business Justification |
|----|------|----------------------|
| P0-1 | SPIKE Nexus activation (Docker Compose, local encrypted storage) | Core value proposition ("agents never touch secrets") is unverified without this. Every demo, every evaluation, every compliance claim depends on this being real. |
| P0-2 | Deep scan LLM configuration (Groq E2E, configurable fail-closed/fail-open) | Without working deep scan, the "AI inspecting AI" story is hollow. Configurable fallback behavior is a setup-time choice, not runtime. |

### P1 -- High Priority

| ID | Item | Business Justification |
|----|------|----------------------|
| P1-1 | Compliance automation (SOC 2 Type II, ISO 27001, CCPA/CPRA, GDPR) | "Biggest win short term." Regulated industries will not adopt without compliance evidence. One-button report generation differentiates from every other MCP security project. |
| P1-2 | Observability fix (OTel spans, per-middleware, cross-service) | Empty dashboards erode trust. If you cannot observe the security controls operating, you cannot convince an evaluator they work. |
| P1-3 | Session persistence with KeyDB | Cross-request exfiltration is a real attack vector. Without session persistence, the exfiltration detection claim is limited to single-request scenarios. |
| P1-4 | mTLS enforcement (all services, both Docker Compose and K8s) | Plaintext internal HTTP is a compliance violation (SOC 2 CC6.6, ISO 27001 A.13.1.1). Evaluators will flag this immediately. |
| P1-5 | Local K8s testing (full stack on Docker Desktop kubeadm) | Supports O1 (git clone to running). EKS requires AWS account and costs; local K8s is the only viable K8s evaluation path. |
| P1-6 | Cosign signature verification (K8s admission control) | Supply chain security for regulated industries. Scope to K8s via sigstore/policy-controller. Docker Compose builds from source (supply chain is the source code). |
| P1-7 | Deep scan fallback policy (configurable, documented degradation) | Groq may be rate-limited or unavailable. Users must understand and explicitly choose their fallback posture. T5-small fine-tuning is deferred; document as known limitation. |
| P1-8 | CLI-based guided setup | Adoption velocity. Non-security-experts are the majority of the OSS audience. |

### P2 -- Important

| ID | Item | Business Justification |
|----|------|----------------------|
| P2-1 | Docker Compose vs K8s pattern audit | Honest documentation of which controls are deployment-specific vs universal. Prevents evaluators from concluding the architecture has gaps when controls are intentionally K8s-only. |
| P2-2 | Multi-agent orchestration patterns | Enterprise teams need agent-to-agent security patterns. |
| P2-3 | SDK / boilerplate reduction | Adoption friction. Agent developers need a simple integration path. |
| P2-4 | Skill download and analysis (skulto integration) | Security scanning of downloaded skills. |
| P2-5 | Registry hot-reload with attestation | Operational necessity for enterprise. Attestation is NOT optional -- unsigned registry updates must be rejected. |
| P2-6 | Performance benchmarking | Latency measurement is required (though security is the primary concern, not performance). Must quantify the cost of security. |
| P2-7 | Security scanning in CI (gosec, trivy, Dependabot) | Credibility. A security reference architecture that doesn't scan its own code is not credible. Must support local runs (GitHub credits may exhaust). |

### P3 -- Strategic / Exploratory

| ID | Item | Business Justification |
|----|------|----------------------|
| P3-1 | Plugin ecosystem (spike) | Commercial sustainability exploration. Not Phase 2 scope. Keep architecturally open. |
| P3-2 | Streaming MCP support | Future protocol evolution. Not Phase 2 scope. |
| P3-3 | T5-small DSPy fine-tuning (informational) | Offline deep scan fallback. Research-grade, not production scope for Phase 2. Document approach and rationale. |
| P3-4 | SPIKE Nexus with Keeper HA (Shamir sharding) | Third priority in SPIKE progression. Deliver if time allows after P0-2 and P1 items. |

---

## 5. Constraints and Non-Functional Requirements

### 5.1 Licensing

Every dependency must have unambiguous open-source licensing suitable for enterprise adoption. No SSPL, no RSAL, no Commons Clause. This is why KeyDB (BSD-3-Clause) replaces Redis, and OpenBAO (MPL-2.0) replaces HashiCorp Vault.

### 5.2 Deployment Parity

All security claims made in documentation must be demonstrable in Docker Compose. If a control is K8s-only (e.g., NetworkPolicies, admission control), it must be explicitly documented as such with the business rationale for why it does not apply to Docker Compose.

### 5.3 Latency

Security is the primary concern, not performance. However, latency through the middleware chain MUST be measured and reported. No specific latency budget is set, but measurements must be available for evaluators to make informed decisions.

### 5.4 Compliance Data Handling

Session data stored in KeyDB and audit logs are subject to GDPR and CCPA requirements:
- Documented data retention policy
- Right-to-deletion mechanism for session data
- Data processing records (GDPR Article 30)
- Clear documentation of what personal data (if any) flows through the gateway

### 5.5 Offline Capability

The system must function in air-gapped or limited-connectivity environments with documented degradation:
- Deep scan without Groq API: configurable fail-closed or fail-open (setup-time choice)
- No cloud KMS dependency for Docker Compose (local encrypted storage)
- Security scanning runnable locally without GitHub Actions

### 5.6 Setup Experience

The target user for initial setup is someone who "doesn't know much about security." The CLI-based setup must:
- Guide through configuration decisions with clear explanations of consequences
- Never silently degrade security posture
- Produce a configuration summary showing what is enabled and what is not

---

## 6. SPIKE Nexus Backend Progression

The SPIKE Nexus integration follows a three-tier progression based on deployment target:

| Tier | Deployment Target | Backend | Priority |
|------|------------------|---------|----------|
| 1 | Docker Compose | Local encrypted storage via SPIKE CLI | P0 |
| 2 | Local K8s / EKS | OpenBAO (open-source Vault fork, MPL-2.0) | P1 |
| 3 | EKS / Cloud | Native KMS (AWS KMS, GCP KMS, Azure Key Vault) | P1 |
| 4 | Production HA | SPIKE Keepers with Shamir key sharding | P3 |

---

## 7. Compliance Framework Mapping

The following table maps Phase 2 deliverables to compliance framework requirements. This is the basis for the automated compliance report.

| Control Area | SOC 2 Type II | ISO 27001 | CCPA/CPRA | GDPR |
|-------------|---------------|-----------|-----------|------|
| Agent identity (SPIFFE/mTLS) | CC6.1 Logical access | A.9.2.1 User registration | -- | Art. 32 Security of processing |
| Authorization (OPA) | CC6.1 Logical access | A.9.4.1 Information access restriction | -- | Art. 25 Data protection by design |
| DLP / content scanning | CC6.7 Data classification | A.8.2.1 Classification of information | 1798.150 Security procedures | Art. 32 Security of processing |
| Tamper-evident audit | CC7.2 Monitoring | A.12.4.1 Event logging | -- | Art. 30 Records of processing |
| Secrets management (SPIKE) | CC6.1 Logical access | A.10.1.1 Cryptographic controls | -- | Art. 32 Security of processing |
| Encrypted transit (mTLS) | CC6.6 Encryption | A.13.1.1 Network controls | 1798.150 Security procedures | Art. 32 Security of processing |
| Session tracking | CC7.2 Monitoring | A.12.4.1 Event logging | -- | Art. 30 Records of processing |
| Data retention/deletion | CC6.5 Data disposal | A.8.3.2 Disposal of media | 1798.105 Right to delete | Art. 17 Right to erasure |
| Deep scan (content classification) | CC7.1 Detection | A.12.2.1 Malware controls | -- | Art. 32 Security of processing |
| Supply chain (cosign, SBOM) | CC7.1 Detection | A.14.2.7 Outsourced development | -- | Art. 28 Processor obligations |

---

## 8. What Is Explicitly Out of Scope for Phase 2

| Item | Reason |
|------|--------|
| Plugin ecosystem / marketplace | Exploratory. Spike only. Keep architecturally open. |
| Streaming MCP support | Future protocol evolution. |
| T5-small DSPy fine-tuning for deep scan | Research-grade. Document approach, defer implementation. |
| Tool/MCP server vendor certification | Not a primary audience for Phase 2. |
| EKS cloud deployment (running on real AWS) | Local K8s validates manifests. Cloud deployment is infrastructure, not security validation. |
| Infrastructure hardening automation | Compliance report covers gateway controls. Infra hardening is documented as recommendations, not automated. |
| Vanta/Drata/vendor-specific compliance integrations | Standalone output (XLSX/CSV/PDF) only. |

---

## 9. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| SPIKE Nexus integration complexity underestimated | P0 blocked, entire Phase 2 delayed | Spike first. If SPIKE integration reveals fundamental issues, surface immediately. |
| Four compliance frameworks is broad | Scope creep in control mapping | Gateway controls only. Document infra recommendations, don't automate them. |
| mTLS in Docker Compose is operationally complex | Setup experience degrades for non-experts | CLI-based setup must handle certificate generation transparently. |
| Deep scan without fallback creates silent security degradation | Users unaware their security posture is reduced | Setup CLI must explicitly inform. Never silently degrade. |
| KeyDB as session store introduces GDPR/CCPA obligations | Compliance risk from session data handling | Document retention policy, right-to-deletion, processing records from day one. |
| Full stack on Docker Desktop K8s may exceed laptop resources | O1 (30-minute setup) fails on resource-constrained machines | Document minimum hardware requirements. Consider resource-light defaults. |
| OpenBAO is younger than HashiCorp Vault | API compatibility gaps, smaller community | Validate API compatibility early. Document any divergences. |

---

## 10. Decision Log

| Decision | Rationale | Date |
|----------|-----------|------|
| KeyDB over Redis | BSD-3-Clause licensing removes enterprise adoption ambiguity | 2026-02-06 |
| OpenBAO over HashiCorp Vault | MPL-2.0 licensing. Open-source fork with compatible API. | 2026-02-06 |
| Standalone compliance reports (not vendor-specific) | Maximum portability. Any evaluator can use XLSX/CSV/PDF. | 2026-02-06 |
| Gateway-scoped compliance only | Tractable scope. Infra hardening documented as recommendations. | 2026-02-06 |
| mTLS all services (not just trust boundary) | Compliance requirement. Evaluators will flag plaintext internal traffic. | 2026-02-06 |
| T5-small fine-tuning deferred | Research-grade work. Groq + configurable fallback is sufficient for Phase 2. | 2026-02-06 |
| Plugin ecosystem is spike only | Exploratory. Not a Phase 2 business objective. | 2026-02-06 |
| Cosign verification scoped to K8s | Docker Compose builds from source. Supply chain is the source code itself. | 2026-02-06 |
| Deep scan fail-closed/fail-open is setup-time config | Informed consent. Users choose their security posture explicitly. | 2026-02-06 |
| KeyDB in Docker Compose | All security claims must be demonstrable in Docker Compose (first-impression environment). | 2026-02-06 |

---

## 11. Glossary

| Term | Definition |
|------|-----------|
| **SPIKE Nexus** | SPIFFE-native secrets management engine. Stores encrypted secrets, issues opaque tokens to agents, redeems tokens at the gateway. Agents never see raw credentials. |
| **Late-binding secrets** | Pattern where agents receive opaque token references instead of actual credentials. The gateway substitutes real secrets at egress time. |
| **OpenBAO** | Open-source fork of HashiCorp Vault (MPL-2.0). API-compatible secrets management backend. |
| **KeyDB** | BSD-3-Clause licensed key-value store, wire-compatible with Redis. Used for session persistence and distributed rate limiting. |
| **SafeZone / DLP** | Data Loss Prevention scanning embedded in the gateway. Detects credentials (fail-closed) and PII (audit-only). |
| **Deep scan** | Async LLM-based content classification for prompt injection and jailbreak detection. Uses guard models (Prompt Guard 2 via Groq). |
| **OTel** | OpenTelemetry. Vendor-neutral observability framework for traces, metrics, and logs. |
| **SVID** | SPIFFE Verifiable Identity Document. X.509 certificate or JWT proving workload identity. |
| **mTLS** | Mutual TLS. Both client and server present certificates, proving identity in both directions. |
| **Walking skeleton** | Thinnest possible end-to-end slice through all layers. Proves integration before building components. |

---

*This document is the single source of truth for Phase 2 business requirements. It will be referenced by the Designer (DESIGN.md), Architect (ARCHITECTURE.md), and Sr. PM (backlog creation). Changes require Business Owner approval.*
