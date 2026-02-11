# Agentic AI Security Reference Architecture
## STRIDE + PASTA Assurance Mapping (Production Profile)

Document version: 1.0  
Date: 2026-02-11  
Audience: Security architecture, audit, legal, risk, platform leadership

---

## 1) Purpose and Scope

This document maps the reference architecture to two threat-model methodologies used by audit and risk functions:

- STRIDE (threat-class coverage)
- PASTA (process and risk lifecycle coverage)

It is designed to support defensibility discussions for production deployments on:

- A leading cloud provider, and/or
- A properly managed Kubernetes environment (managed or self-hosted)

This is an assurance mapping, not a legal attestation. Claims here are tied to implementation artifacts currently present in this repository.

---

## 2) Assumptions for Production Defensibility

Defensibility statements in this document assume the following are true in production:

1. Workload identity is SPIFFE/SPIRE based with mTLS enforced for service-to-service traffic.
2. Gateway remains the mandatory policy enforcement point for all MCP traffic.
3. Policy, registry, image, and model artifacts are promoted through signed and reviewed supply-chain gates.
4. Audit events are shipped to immutable/append-only retention systems.
5. Break-glass changes are time-boxed and auditable.
6. The operating model follows the 3 Rs (Repair, Rotate, Repave) as a continuous practice, not a one-time design goal.

If these assumptions are not met, coverage downgrades from "defensible" to "partially defensible".

### 2.1 3 Rs Operating Doctrine

- Repair: platform uses self-healing and redundancy controls for critical services.
- Rotate: identities and secrets are short-lived and automatically rotated.
- Repave: environments can be rebuilt rapidly to remove persistence and restore trusted state.

This doctrine is central to long-term resilience against both routine failures and persistent adversaries.

---

## 3) Control Evidence Baseline (Repository Anchors)

Primary architectural references:

- `agentic-ai-security-reference-architecture.md`
- `POC/docs/ARCHITECTURE.md`

Representative implementation evidence:

- Tool registry verification and poisoning checks: `POC/internal/gateway/middleware/tool_registry.go`
- Step-up gating and risk scoring: `POC/internal/gateway/middleware/step_up_gating.go`
- Response firewall and handle-ization: `POC/internal/gateway/middleware/response_firewall.go`
- DLP scanner: `POC/internal/gateway/middleware/dlp.go`
- OPA authorization policies: `POC/config/opa/mcp_policy.rego`
- Exfiltration rules: `POC/config/opa/exfiltration.rego`
- Audit hash chain and verification: `POC/internal/gateway/middleware/audit.go`, `POC/internal/gateway/middleware/audit_verify.go`
- K8s admission for signed/digest-pinned images: `POC/infra/eks/admission/constraints/enforce-image-signature.yaml`, `POC/infra/eks/admission/constraints/enforce-image-digest.yaml`
- Compliance taxonomy and generator: `POC/tools/compliance/control_taxonomy.yaml`, `POC/tools/compliance/generate.py`
- GDPR ROPA and deletion workflow: `POC/docs/compliance/gdpr-article-30-ropa.md`, `POC/internal/gateway/middleware/gdpr_delete.go`

---

## 4) STRIDE Mapping to Architecture

### 4.1 Spoofing (S)

Threat focus:
- Impersonated agent/tool workloads
- Service identity spoofing in east-west traffic

Current controls:
- SPIFFE/SPIRE workload identity and SVID-based mTLS
- Trust-domain and identity checks in gateway auth middleware
- K8s admission constraints reducing rogue workload introduction

Coverage rating: High

Residual gaps:
- No explicit hardware-backed attestation requirement across all deployment profiles
- Non-K8s deployments need stronger node attestation standardization

### 4.2 Tampering (T)

Threat focus:
- Tool metadata or schema mutation (rug pull)
- Policy/registry/config mutation
- Artifact supply-chain manipulation

Current controls:
- Tool hash verification and poisoning checks
- UI resource hash verification and gating
- Signature-aware hot reload path for registry updates
- K8s digest and signature admission policies

Coverage rating: High

Residual gaps:
- Model artifact signing/verification is defined architecturally but not uniformly enforced end-to-end
- Signed policy bundle verification can be strengthened in non-K8s profiles

### 4.3 Repudiation (R)

Threat focus:
- Inability to prove who did what, when, and under which decision policy

Current controls:
- Structured JSON audit events with trace/session/decision identifiers
- Tamper-evident hash chain for audit event continuity
- Compliance report generation path from control taxonomy + evidence artifacts

Coverage rating: High

Residual gaps:
- Immutable retention is partly deployment-dependent (must be implemented in cloud object lock/WORM)
- Legal hold runbooks and chain-of-custody operations are not fully codified as executable procedures

### 4.4 Information Disclosure (I)

Threat focus:
- Secrets/PII exfiltration through compromised agent behavior
- Sensitive response data leakage via legitimate tools

Current controls:
- Late-binding token substitution pattern (agent never receives raw secret)
- DLP scanning and risk flags
- Response firewall with sensitive-response handle-ization
- Egress and destination controls in policy
- Documented path to enforce model-provider egress controls at the same boundary

Coverage rating: High (conditional)

Residual gaps:
- Some DLP failure paths are configurable and can fail open if not hardened per risk class
- Cross-border data transfer governance for external AI scanning providers requires legal controls (SCCs/DPIA)
- External LLM provider endpoint attestation/residency enforcement is not yet fully standardized

### 4.5 Denial of Service (D)

Threat focus:
- Gateway overload, scanner outage, dependency failure cascades

Current controls:
- Request size limits, rate limiting, circuit breakers
- Explicit failure mode table and degraded modes
- Observability and alerting patterns

Coverage rating: Medium-High

Residual gaps:
- HA/SLO targets and failure-injection evidence are not yet formally packaged for auditors
- Multi-region recovery and tested RTO/RPO plans are not documented at assurance depth

### 4.6 Elevation of Privilege (E)

Threat focus:
- Prompt injection driving privileged tools/actions
- Lateral movement from lower-risk to higher-risk capabilities

Current controls:
- OPA tool authorization by identity + path/destination rules
- Step-up gating and risk-score thresholds
- Session-context exfiltration pattern detection
- Approval/capability model described for high-risk actions

Coverage rating: High

Residual gaps:
- Formal JIT approval workflow integration and reviewer accountability trail needs standardized implementation
- Delegation-chain controls (actor vs subject) are still maturing for complex multi-agent workflows

---

## 5) STRIDE Coverage Summary

| STRIDE Element | Coverage | Why Defensible Today | Main Remaining Gap |
|---|---|---|---|
| Spoofing | High | SPIFFE/SPIRE identity + mTLS + auth middleware | Uniform strong attestation in all environments |
| Tampering | High | Hash verification, signed reload paths, admission controls | Model/policy artifact verification consistency |
| Repudiation | High | Hash-chained audit + decision/trace correlation | Immutable retention + legal hold operationalization |
| Info Disclosure | High (conditional) | Late-binding secrets + DLP + response firewall | Fail-open edge cases and transfer governance |
| DoS | Medium-High | Rate limits, breakers, explicit failure modes | Formal resilience evidence package |
| Elevation of Privilege | High | OPA least privilege + step-up gating + risk scoring | JIT approval and delegation rigor |

---

## 6) PASTA Mapping to Architecture

### Stage 1: Define Business and Security Objectives

Evidence:
- Business drivers and compliance expectations: `POC/docs/BUSINESS.md`
- Architecture objective framing: `agentic-ai-security-reference-architecture.md`

Assessment: Strong

Notes:
- Objectives are explicit: secure agent/tool mediation, compliance evidence, and production deployment portability.

### Stage 2: Define Technical Scope

Evidence:
- System and deployment architecture: `POC/docs/ARCHITECTURE.md`
- EKS and deployment assets: `POC/infra/eks/`

Assessment: Strong

Notes:
- Scope includes identity plane, policy engine, gateway, observability, compliance tooling, and deployment variants.

### Stage 3: Application Decomposition

Evidence:
- Middleware chain, trust boundaries, component responsibilities: `agentic-ai-security-reference-architecture.md`, `POC/docs/ARCHITECTURE.md`

Assessment: Strong

Notes:
- Architecture decomposes control points clearly enough for attack-surface reasoning.

### Stage 4: Threat Analysis

Evidence:
- Threat landscape and analysis sections: `agentic-ai-security-reference-architecture.md`
- Existing security review: `security_best_practices_report.md`

Assessment: Strong

Notes:
- Threats include MCP-specific vectors (poisoning, rug pull, exfiltration, active UI content), not just generic web threats.

### Stage 5: Vulnerability Analysis

Evidence:
- Security baseline and findings process: `POC/docs/security/baseline.md`
- Tool-specific middleware and policy implementations under `POC/internal/gateway/middleware/` and `POC/config/opa/`

Assessment: Medium-High

Notes:
- The architecture defines practical vulnerability classes and controls; coverage is stronger in design than in continuously published vulnerability management metrics.

### Stage 6: Attack Modeling and Simulation

Evidence:
- E2E scenarios and validation scripts: `POC/tests/e2e/`
- Integration and policy tests: `POC/tests/integration/`, `POC/config/opa/*_test.rego`

Assessment: Medium-High

Notes:
- Simulation exists and is substantive; formal red-team/adversary-emulation playbooks are still limited.

### Stage 7: Risk and Impact Analysis

Evidence:
- Risk-adaptive gating model and operational risk framing in architecture docs
- Compliance reporting and evidence generation toolchain

Assessment: Medium

Notes:
- Qualitative risk treatment is strong, but enterprise-grade quantitative risk register linkage (loss magnitude, appetite thresholds, KRIs) is not yet fully formalized.

---

## 7) PASTA Coverage Summary

| PASTA Stage | Coverage | Defensibility Position |
|---|---|---|
| Stage 1 - Objectives | Strong | Clear security and compliance outcomes are defined |
| Stage 2 - Technical Scope | Strong | Production control plane and deployment footprint are explicit |
| Stage 3 - Decomposition | Strong | Components and trust boundaries are well decomposed |
| Stage 4 - Threat Analysis | Strong | Threat taxonomy includes agentic/MCP-native vectors |
| Stage 5 - Vulnerability Analysis | Medium-High | Good control mapping, needs stronger continuous vuln evidence packet |
| Stage 6 - Attack Simulation | Medium-High | Test scenarios exist, needs formal adversary playbooks |
| Stage 7 - Risk/Impact | Medium | Needs tighter integration with enterprise risk quantification |

---

## 8) Prioritized Gap Register (Auditor/Legal/Risk View)

### G-01 (High): HIPAA-specific control mapping and operational safeguards are not first-class

Impact:
- Weakens defensibility for PHI workloads and covered-entity/business-associate scrutiny.

What is missing:
- Explicit HIPAA Security Rule control matrix and operating procedures
- BAA, minimum necessary standard workflows, and HIPAA incident/breach response mappings

Priority recommendation:
- Create HIPAA crosswalk with technical + administrative controls and evidence owners.

### G-02 (High): Immutable retention and legal hold are architecture-described but not fully operationalized as runbooks/evidence

Impact:
- Repudiation/eDiscovery defensibility is reduced during legal discovery.

What is missing:
- Evidence of object lock/WORM retention, legal hold activation workflow, and custody approvals

Priority recommendation:
- Implement and test legal hold playbook with periodic drill evidence.

### G-03 (High): Supply-chain integrity for model artifacts is not uniformly enforced

Impact:
- Compromised model weights can degrade security detections and trustworthiness.

What is missing:
- Standard startup/runtime verification for model digests/signatures across all deployment profiles

Priority recommendation:
- Enforce model artifact signature and digest validation at deploy + startup.

### G-04 (Medium): Cross-border data transfer governance for optional external scanning providers is conditional

Impact:
- GDPR/CPRA legal risk if transfer safeguards are incomplete.

What is missing:
- Institutionalized SCC/DPIA controls tied to feature flags and deployment policy

Priority recommendation:
- Enforce policy guardrails that disable external scanning unless legal prerequisites are attested.

### G-05 (Medium): Risk quantification and executive risk acceptance workflow needs formalization

Impact:
- Harder to defend residual risk decisions during audits.

What is missing:
- Formal KRIs, risk appetite thresholds, signed exceptions, and expiration-driven review cycle

Priority recommendation:
- Integrate architecture risk findings into enterprise risk register with owner/accountability.

### G-06 (Medium): Non-K8s production parity controls need stronger prescriptive baseline

Impact:
- Portability claims may outpace realized control equivalence outside Kubernetes.

What is missing:
- Mandatory baseline profile for VM/non-K8s deployments (identity, egress, integrity, immutable audit)

Priority recommendation:
- Publish non-K8s minimum control profile with pass/fail go-live checklist.

### G-07 (Medium): DLP rule CRUD introduces a new control-plane tampering surface

Impact:
- If DLP patterns become editable via API/CLI without strong governance, attackers or misconfigurations can silently weaken detection/blocking or induce DoS via unsafe regex.

What is missing:
- A mandated rule lifecycle with RBAC, signed/versioned rule bundles, validation gates, staged rollout, full audit trail, and rollback guarantees.

Priority recommendation:
- Treat DLP rule management as a Tier-0 security control plane with change-management controls equivalent to policy bundle governance.

### G-08 (High): External LLM provider traffic is not yet governed as a first-class gateway control plane

Impact:
- Model API access may bypass centralized controls, weakening secret management, endpoint trust validation, and data residency enforcement.

What is missing:
- Standardized gateway mediation for model egress with credential-by-reference, provider allowlists, TLS endpoint identity policy, DNS integrity checks, and jurisdiction gating.

Priority recommendation:
- Extend the gateway boundary to mediate external model-provider access with the same enforcement and audit rigor used for tools.

---

## 9) Defensibility Position (Executive Summary)

If implemented with the production assumptions in Section 2, this architecture is defensible under both STRIDE and PASTA because:

1. Threat classes are addressed with layered, testable controls at identity, policy, content, and audit layers.
2. Control points are centralized at the gateway, reducing policy drift and improving evidentiary consistency.
3. Supply-chain and trust-boundary concerns are explicitly represented, including MCP-specific attack vectors.
4. Residual risks are known and can be treated with concrete, near-term remediation actions.

Current posture is best characterized as:
- Strong technical defensibility for STRIDE coverage
- Strong process framing for PASTA Stages 1-4
- Maturing assurance maturity for Stages 5-7, contingent on operational evidence program completion
