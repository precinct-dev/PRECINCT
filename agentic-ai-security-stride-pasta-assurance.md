# Agentic AI Security Reference Architecture
## STRIDE + PASTA Assurance Mapping (Production Profile)

Document version: 1.2  
Date: 2026-02-11  
Audience: Security architecture, audit, legal, risk, platform leadership

---

## 1) Purpose and Scope

This document maps the reference architecture to:

- STRIDE (threat-class coverage)
- PASTA (risk lifecycle coverage)

It incorporates the approved **Phase 3 architectural direction** centered on the **Unified Agentic Security Gateway System (UASGS)** and this document now reflects the latest hardening pass intended to close architecture-level (non-operational) gaps.

Deployment scope assumed:

- Leading cloud provider and/or
- Properly managed Kubernetes environment

This is an assurance mapping, not legal advice or an attestation.

---

## 2) Assumptions for Production Defensibility

Defensibility statements in this document assume:

1. Workload identity is SPIFFE/SPIRE based and mTLS is enforced.
2. UASGS is the mandatory policy boundary for ingress admission, model egress, tool execution, and governed memory I/O.
3. Loop governance is enforced externally via immutable run envelopes (boundary-only baseline), without requiring framework loop-engine replacement.
4. Model-provider credentials are reference-based (not embedded in agent services).
5. Policy, registry, image, and runtime artifact promotion is signed and reviewed.
6. Audit events are retained in immutable/append-only systems.
7. Break-glass operations are time-boxed, reason-coded, and reviewed.
8. Operating model follows the 3 Rs: Repair, Rotate, Repave.
9. Production profile defaults from Phase 3 v1.1 are applied (`prod_standard` and `prod_regulated_hipaa`).

### 2.1 3 Rs Operating Doctrine

- Repair: self-heal and recover quickly through redundant, observable services.
- Rotate: use short-lived identity and referential secrets by default.
- Repave: rebuild trusted runtime state on demand to reduce persistent footholds.

---

## 3) Control Evidence Baseline (Repository Anchors)

Primary references:

- `agentic-ai-security-reference-architecture.md`
- `agentic-ai-security-phase3-proposal.md`
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

## 4) Posture Delta From Phase 3 Architecture

This section captures the impact of the Phase 3 proposal itself (design-level uplift). Implementation evidence for these controls is still required before final auditor claims.

| Control Plane | Pre-Phase 3 Posture | Phase 3 Design Posture | Net Effect |
|---|---|---|---|
| LLM egress | Fragmented, app-specific provider handling | UASGS-mediated provider governance, trust checks, residency + budget policy | Major uplift in disclosure, supplier, and audit defensibility |
| Loop control | Inconsistent per framework | External immutable envelopes and reason-coded halts (boundary-only baseline) | Stronger DoS/EoP resilience without framework lock-in |
| Ingress | Not first-class across webhook/queue/schedule | Connector-based normalized ingress admission (non-MITM default) | Better spoofing/tampering coverage for event-driven agents |
| Context engineering | Detection-oriented, uneven enforcement | Mandatory admission model: no-scan-no-send / no-verification-no-load | Large uplift in prompt-injection and data handling consistency |
| RLM/repl flows | Largely ungoverned pattern | Explicit RLM controls (sandbox, recursion limits, sub-call mediation) | Reduced emerging-runtime risk and better auditability |
| DLP control plane | Static or ad hoc rule lifecycle | RuleOps lifecycle with signing, staged rollout, rollback, and immutable audit | Closes major tampering gap for rule CRUD |
| HIPAA prompt safety | Implicit/partial handling | Regulated profile with deny/tokenize defaults and minimum-necessary controls | Closes core architecture gap for prompt-bound PHI/PII handling |

---

## 5) STRIDE Mapping to Architecture

### 5.1 Spoofing (S)

Threat focus:

- Workload identity impersonation
- Fake ingress sources
- Spoofed model-provider endpoints

Controls:

- SPIFFE/SPIRE SVID + mTLS
- Ingress source authentication (mTLS/JWT/HMAC/signature)
- UASGS endpoint trust policy for model egress
- Production default for mediated model egress (policy + identity + network gates)

Coverage rating:

- Current: High
- Target with Phase 3 implementation: Very High

Residual gaps:

- Hardware/root-of-trust attestation is not uniformly required across all deployment profiles.
- Ingress connector certification remains an operational governance dependency.

### 5.2 Tampering (T)

Threat focus:

- Tool/registry/policy mutation
- DLP rule abuse via CRUD surfaces
- Artifact/skill tampering in download path

Controls:

- Tool hash verification and poisoning checks
- Signed policy and artifact supply-chain gates
- DLP RuleOps lifecycle (RBAC/SOD, validation, signing, staged rollout, rollback)
- Artifact proxy + signature/scan gates (Phase 3)

Coverage rating:

- Current: High (tool-focused)
- Target with Phase 3 implementation: Very High

Residual gaps:

- DLP RuleOps assurance is now primarily an operations-evidence task (e.g., dual-approval and rollback drill records).
- Artifact intake controls require runtime enforcement verification in production telemetry.

### 5.3 Repudiation (R)

Threat focus:

- Inability to prove who did what, when, and under which policy decision

Controls:

- Structured JSON audits with trace/session/decision ids
- Hash-chained audit continuity
- UASGS unified audit taxonomy v2 across ingress/model/tool/memory/loop/RLM/context-admission

Coverage rating:

- Current: High
- Target with Phase 3 implementation: Very High

Residual gaps:

- Immutable retention and legal hold operations require stronger operational drill evidence.
- Auditor-ready packaged evidence cadence still depends on control-operations maturity.

### 5.4 Information Disclosure (I)

Threat focus:

- Secrets/PII exfiltration through model/tool/context paths
- Prompt injection and unsafe context ingestion
- Cross-border data transfer violations

Controls:

- Late-binding secret substitution and referential credentials
- DLP and response firewall
- Model-provider residency and endpoint policy gates
- Mandatory context admission controls:
  - no-scan-no-send
  - no-provenance-no-persist
  - no-verification-no-load
- HIPAA prompt safety profile with deny/tokenize defaults and minimum-necessary preprocessing

Coverage rating:

- Current: High (conditional)
- Target with Phase 3 implementation: Very High

Residual gaps:

- High-risk fail-closed defaults now exist in architecture; remaining work is operational verification.
- Legal prerequisites for external processors (DPIA/SCC/contract terms) remain organizational dependencies.

### 5.5 Denial of Service (D)

Threat focus:

- Runaway loops
- Provider outages and budget exhaustion
- Gateway/connector bottlenecks

Controls:

- Rate limits, request limits, and circuit breakers
- Immutable run envelopes (step/tool/model/time/cost/failover bounds)
- Provider fallback policy and explicit halt reason codes

Coverage rating:

- Current: Medium-High
- Target with Phase 3 implementation: High

Residual gaps:

- Formal HA/SLO evidence package and failure-injection cadence are not yet audit-packaged.
- Multi-region DR/RTO/RPO validation remains to be codified as repeatable evidence.

### 5.6 Elevation of Privilege (E)

Threat focus:

- Prompt injection driving privilege jumps
- Hidden sub-call escalation in RLM/REPL workflows
- Cross-plane policy bypass attempts

Controls:

- OPA least-privilege policy for capabilities
- Step-up gating and risk scoring
- Boundary-only loop governance with immutable limits
- RLM sub-call mediation through model egress controls

Coverage rating:

- Current: High
- Target with Phase 3 implementation: Very High

Residual gaps:

- JIT approval workflow and reviewer-accountability controls need standardized implementation.
- Delegation-chain modeling for complex multi-agent subject/actor flows needs maturity.

---

## 6) STRIDE Coverage Summary

| STRIDE Element | Current Coverage | Target Coverage (Phase 3 Implemented) | Main Remaining Gap |
|---|---|---|---|
| Spoofing | High | Very High | Uniform attestation + connector governance operations |
| Tampering | High | Very High | Operating-evidence maturity for RuleOps and artifact enforcement |
| Repudiation | High | Very High | Immutable retention/legal hold execution rigor |
| Info Disclosure | High (conditional) | Very High | Legal transfer prerequisites + profile verification evidence |
| DoS | Medium-High | High | Audit-ready resilience/DR evidence packages |
| Elevation of Privilege | High | Very High | JIT approvals + delegation-chain rigor |

---

## 7) PASTA Mapping to Architecture

### Stage 1: Define Business and Security Objectives

Assessment: Strong

Phase 3 effect:

- Explicit objectives now include model egress governance, ingress governance, context admission invariants, and loop-bound autonomy controls.

### Stage 2: Define Technical Scope

Assessment: Strong

Phase 3 effect:

- Scope now explicitly covers five agentic planes plus policy/audit/identity/secrets planes under one UASGS contract.

### Stage 3: Application Decomposition

Assessment: Strong

Phase 3 effect:

- Clear subsystem boundaries: LLM plane, Tool Plane, Context/Memory plane, Loop Governance plane, Ingress plane.
- Boundary-only governance model lowers integration friction with framework-native loops.

### Stage 4: Threat Analysis

Assessment: Strong

Phase 3 effect:

- Threat coverage now includes RLM trajectory risk, provider budget failures, ingress connector abuse, and context/artifact supply-chain poisoning.

### Stage 5: Vulnerability Analysis

Assessment: Medium-High

Phase 3 effect:

- Vulnerability classes are richer and closer to real deployment patterns.
- Remaining gap is continuous vulnerability-management evidence and control effectiveness cadence.

### Stage 6: Attack Modeling and Simulation

Assessment: Medium-High

Phase 3 effect:

- Simulation scope should expand to boundary-only loop stress tests, ingress replay/forgery, provider brownouts, RLM recursion abuse, and context-admission bypass attempts.

### Stage 7: Risk and Impact Analysis

Assessment: Medium-High

Phase 3 effect:

- Risk treatment becomes more explicit via run envelopes, policy reason codes, and model-provider budget/fallback policies.
- Risk-acceptance governance still requires stronger executive workflow formalization.

---

## 8) PASTA Coverage Summary

| PASTA Stage | Current | With Phase 3 Direction | Remaining Gap |
|---|---|---|---|
| Stage 1 Objectives | Strong | Stronger and more explicit | None material |
| Stage 2 Scope | Strong | Stronger multi-plane scope | None material |
| Stage 3 Decomposition | Strong | Strong with clearer boundaries | None material |
| Stage 4 Threat Analysis | Strong | Stronger emerging-pattern coverage | Keep updating threat library |
| Stage 5 Vulnerability Analysis | Medium-High | Medium-High to High potential | Continuous evidence and metrics maturity |
| Stage 6 Attack Modeling | Medium-High | High potential | Formal adversary-emulation cadence |
| Stage 7 Risk/Impact | Medium-High | High potential | Executive risk acceptance operationalization |

Re-assessment result:

- The Phase 3 v1.1 hardening pass closes the major architecture-level (non-operational) gaps previously flagged around model egress bypass, context admission defaults, DLP CRUD scaffolding, and HIPAA prompt-safety technical controls.
- Remaining gaps are predominantly operationalization, legal governance, and audit-evidence cadence concerns.

---

## 9) Prioritized Gap Register (Auditor/Legal/Risk View)

After the Phase 3 v1.1 hardening pass, remaining gaps are predominantly operational/human-process:

### G-01 (Critical): HIPAA-specific governance and evidence program remains incomplete

Required action:

- Operate a HIPAA-focused control/evidence framework (45 CFR 164.308/310/312/314/316), including BAAs and incident workflows.

### G-02 (High): Immutable retention, legal hold, and custody controls require recurring operational drills

Required action:

- Run and record legal hold/WORM retention drills and custody validations on a defined schedule.

### G-03 (High): SOC 2 Type 2 operating-effectiveness cadence is not yet fully institutionalized

Required action:

- Establish sampling plans, owner attestations, exception SLAs, and internal-audit checkpoints.

### G-04 (Medium): Connector and RuleOps controls need sustained conformance evidence

Required action:

- Produce recurring evidence for connector conformance checks, RuleOps approvals, and rollback readiness.

### G-05 (Medium): Privacy/legal transfer governance remains an organizational dependency

Required action:

- Ensure DPIA/SCC and processor-contract controls are embedded in deployment gates and exceptions.

### G-06 (Medium): Resilience/DR proof remains an evidence packaging challenge

Required action:

- Produce audit-ready RTO/RPO, failure-injection, and multi-region recovery evidence artifacts.

---

## 10) Defensibility Position (Executive Summary)

Overall posture is stronger after the Phase 3 architecture update because core modern-agentic risk surfaces are now explicitly governed in design:

- model egress,
- event ingress,
- loop autonomy bounds,
- context admission,
- and RLM execution.

What remains is mostly implementation and operating-evidence maturity, not conceptual architecture deficiency.

Following the latest hardening pass, there are no major architecture-level gaps left in this STRIDE/PASTA view that can be closed purely by additional design text; remaining items are execution and governance operations.

Practical readout:

- SOC 2 Type 2 / ISO 27001 / GDPR / CCPA-CPRA: defensible trajectory with focused evidence hardening.
- HIPAA: still requires dedicated compliance and legal-operational uplift before readiness claims.
