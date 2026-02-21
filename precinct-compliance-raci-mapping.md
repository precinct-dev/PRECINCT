# PRECINCT
## Compliance Crosswalk + RACI Operating Model (Production)

PRECINCT -- Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools

Document version: 1.2  
Date: 2026-02-11  
Audience: Audit, legal, privacy, risk, security leadership, platform operations

---

## 1) Purpose

This document shows how the architecture can be defended for SOC 2 Type 2, ISO 27001, CCPA/CPRA, GDPR, and HIPAA when deployed in production.

It has been updated to reflect the approved Phase 3 architecture direction:

- PRECINCT Gateway
- Five governed planes (LLM, Context/Memory, Tool, Loop, Ingress)
- Mandatory context admission invariants
- RLM governance model
- DLP RuleOps control plane
- HIPAA prompt safety profile (`prod_regulated_hipaa`)

This is a control and operating-model mapping, not legal advice.

The operating doctrine remains the 3 Rs:

- Repair
- Rotate
- Repave

---

## 2) Roles Used in RACI

- CISO: Executive accountability for security posture and risk acceptance.
- Security Architecture: Control design authority and policy guardrail owner.
- Platform Engineering: Cloud/Kubernetes platform and shared-control implementation owner.
- SRE/Operations: Runtime reliability, service operations, and production runbooks.
- Application/Agent Engineering: Agent-framework integration and app behavior owner.
- GRC/Compliance: Control library ownership, evidence cadence, audit coordination.
- Privacy Office/DPO: Privacy-by-design, DSAR operations, transfer governance.
- Legal Counsel: Regulatory interpretation, contracts, BAAs, SCCs, notifications.
- Internal Audit: Independent control testing and assurance.
- Security Operations (SecOps/IR): Monitoring, detection, triage, and incident handling.

Note:

- If FinOps is a separate function, map provider budget ownership from Platform Engineering into FinOps as Accountable/Responsible for cost thresholds.

---

## 3) Posture Delta From Phase 3 Design

| Area | Before Phase 3 | After Phase 3 Design Update | Remaining Requirement |
|---|---|---|---|
| LLM provider governance | Fragmented, app-level | Mandatory model mediation (policy + identity + network gates) + trust/residency/budget policy | Sustained control-operation evidence |
| Event ingress governance | Uneven across webhook/queue triggers | Connector-based normalized ingress admission + conformance gates | Connector ownership and 24x7 support model |
| Loop controls | Framework-specific, hard to audit consistently | External immutable envelopes and reason-coded halts | Runtime adoption and alerts/runbooks |
| Context safety | Detection-oriented, non-uniform enforcement | No-scan-no-send + minimum-necessary + artifact verification invariants | Ongoing verification evidence by environment |
| RLM runtime | Emerging pattern with weak standard controls | Explicit sandbox/sub-call/budget controls | GA profile defaults + control effectiveness evidence |
| DLP rule lifecycle | Static/ad hoc or code-bound patterns | DLP RuleOps lifecycle (RBAC/SOD, validate, approve, sign, canary, rollback) | RuleOps drill and approval evidence |
| HIPAA prompt path | Partial and policy-implicit | `prod_regulated_hipaa` deny/tokenize defaults + override reason codes | Legal/operational HIPAA governance evidence |

---

## 4) Control-Family Crosswalk (Architecture to Accreditation)

Legend:

- Implemented: technical capability exists and is evidenced in repo/runtime
- Partial: capability is designed/partially implemented, but operating evidence or mandatory enforcement is incomplete
- Gap: material missing control or ownership/evidence model

| Control Family | Architecture Mechanism | SOC 2 Type 2 | ISO 27001 | CCPA/CPRA | GDPR | HIPAA | Status |
|---|---|---|---|---|---|---|---|
| Workload identity and strong auth | SPIFFE/SPIRE SVIDs + mTLS | CC6.1, CC6.7 | Access/network/crypto controls | Reasonable security baseline | Art. 32 | 164.312(d), 164.312(e)(1) | Implemented |
| Policy-based authorization and least privilege | OPA policy engine + capability constraints | CC6.1, CC6.6 | Access and privileged access controls | Access minimization expectation | Art. 25, Art. 32 | 164.312(a)(1), 164.308(a)(4) | Implemented |
| Secret protection and non-exfiltration pattern | Referential credentials + late-binding substitution | CC6.1, CC6.7 | Crypto/secret management controls | Security safeguards | Art. 32 | 164.312(a), 164.312(c)(1) | Implemented |
| Data loss/exfiltration controls | DLP + response firewall + step-up gating | CC6.6, CC7.1 | Monitoring/data protection controls | 1798.150 risk reduction posture | Art. 25, Art. 32 | 164.312(c)(1), 164.308(a)(1) | Partial |
| LLM provider egress governance | Mandatory model mediation with policy+identity+network gates, trust policy, residency, budget/fallback policy | CC6.6, CC7.2 | Supplier/network/data transfer controls | Service provider controls expectation | Art. 28, Art. 44+, Art. 32 | 164.308(b)(1), 164.312(e)(1) | Partial |
| Ingress governance | Connector-based source auth/replay/schema/idempotency + connector conformance gates | CC6.6, CC7.1 | Network/input/change controls | Security safeguards | Art. 25, Art. 32 | 164.308(a)(1), 164.312(e)(1) | Partial |
| Loop governance | Immutable run envelopes, halt reason taxonomy, operator stop controls | CC7.1, CC7.2 | Operational security/resilience controls | Security safeguards | Art. 32(1)(b),(d) | 164.308(a)(1), 164.308(a)(7) | Partial |
| Context engineering admission | No-scan-no-send, no-provenance-no-persist, no-verification-no-load, minimum-necessary | CC6.6, CC7.2 | Input validation/data handling controls | Sensitive PI safeguards | Art. 25, Art. 32 | 164.312(c)(1), 164.308(a)(1) | Partial |
| RLM governance | REPL sandbox, recursion/sub-call limits, mediated sub-calls | CC6.6, CC7.1 | Secure operations/change controls | Security safeguards | Art. 32 | 164.308(a)(1), 164.312(c)(1) | Partial |
| Auditability and evidence chain | Unified event taxonomy + hash chain + trace correlation | CC7.2 | Logging/monitoring controls | Accountability support | Art. 30, Art. 5(2) | 164.312(b), 164.316(b)(1) | Partial |
| DLP RuleOps governance | RuleOps RBAC/SOD + approvals + signing + canary + rollback + immutable audit | CC6.7, CC7.2 | Change/logging controls | Security safeguards | Art. 24, Art. 32 | 164.308(a)(1), 164.316(b)(1) | Partial |
| HIPAA prompt safety profile | `prod_regulated_hipaa` deny/tokenize defaults, prompt minimization, restricted override path | CC6.6, CC7.2 | Data handling and operations controls | Sensitive PI safeguards | Art. 25, Art. 32 | 164.312(c)(1), 164.308(a)(1) | Partial |
| Supply-chain integrity | Signed image/digest admission + artifact fetch/proxy model | CC6.7, CC7.1 | Supplier/dev/change controls | Security safeguards | Art. 32 | 164.308(a)(1), 164.312(c)(1) | Partial |
| Privacy rights operations | ROPA + deletion orchestration + retention controls | CC6/CC7 supporting controls | Lifecycle/retention controls | 1798.105 deletion rights | Art. 17, Art. 30 | 164.316 policies/procedures support | Partial |
| Incident response and legal response | Detection + explainable audit + playbooks + legal hold hooks | CC7.x | Incident management controls | Breach response obligations | Art. 33/34 support | 164.308(a)(6) | Partial |
| Third-party/processor governance | Vendor due diligence + transfer gating + contractual controls | CC9 context | Supplier relationship controls | Service provider obligations | Art. 28, Art. 44+ | 164.308(b)(1) | Partial |
| Business continuity and resilience | Circuit breakers, HA patterns, repave readiness | Availability criteria | Continuity/resilience controls | Service reliability implication | Art. 32(1)(b) | 164.308(a)(7) | Partial |

---

## 5) RACI Matrix - Security and Compliance Operations

### 5.1 Core Security Control Lifecycle

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| Threat model baseline (STRIDE/PASTA) | A | R | C | C | C | C | C | C | C | I |
| PRECINCT Gateway policy and schema lifecycle (policy input v2, audit taxonomy v2) | I | A/R | R | C | C | C | I | I | C | I |
| Identity and mTLS posture management | I | A | R | R | I | I | I | I | C | I |
| Secrets/referential credential controls | I | A | R | R | C | I | I | I | C | I |
| LLM provider catalog and trust policy (endpoint, residency, budget, fallback) | I | A | R | R | C | C | C | C | C | I |
| Mandatory model mediation enforcement (policy + identity + network gates) | I | A | R | R | C | C | I | I | C | I |
| Ingress connector controls and certification | I | A | R | R | C | C | C | C | C | I |
| DLP RuleOps lifecycle and release governance | I | A | R | C | C | C | C | C | C | I |
| Loop envelope defaults and halt-code governance | I | A | C | R | R | C | I | I | C | I |
| Context admission policy tuning (no-scan-no-send) | I | A | R | C | C | C | C | C | C | I |
| HIPAA prompt-safety profile and override governance | I | A | C | C | R | C | A/R | A/R | C | I |
| Artifact intake proxy + verification controls | I | A | R | R | C | C | C | C | C | I |
| RLM profile approvals (GA vs experimental) | I | A | C | C | R | C | C | C | C | I |
| Supply-chain admission policy (signatures/digests) | I | A | R | C | I | C | I | I | C | I |
| Runtime monitoring and alert triage | I | C | C | R | I | I | I | I | A/R | I |
| Incident handling and containment | A | C | C | R | C | I | C | C | A/R | I |
| Formal risk acceptance and exception approval | A/R | C | C | C | I | C | C | C | C | I |

### 5.2 Privacy, Legal, and Regulated Data Workflow

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| Data classification and tagging policy | I | C | I | I | C | C | A/R | C | I | I |
| GDPR/CCPA/CPRA deletion workflow operations | I | C | C | R | I | C | A/R | C | I | I |
| ROPA maintenance and processing records | I | I | I | I | I | C | A/R | C | I | I |
| Cross-border transfer controls (DPIA/SCC + residency policy) | I | C | C | I | I | C | A/R | A/R | I | I |
| HIPAA applicability and BAA governance | C | C | I | I | I | C | C | A/R | I | I |
| Legal hold activation and evidence custody | I | I | C | R | I | C | C | A/R | C | I |
| Model-provider contract and processor governance | I | C | I | I | I | C | C | A/R | I | I |

### 5.3 Accreditation Readiness and Audit Cadence

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| SOC 2 Type 2 evidence period planning | A | C | C | C | I | R | I | C | C | C |
| ISO 27001 SoA and risk treatment alignment | A | C | C | C | I | R | C | C | C | C |
| Control testing and remediation tracking | I | C | R | R | C | A | I | I | C | C |
| Phase 3 control effectiveness dashboard (ingress/model/loop/context/RLM) | I | C | R | R | C | A | C | I | C | C |
| Pre-audit readiness review | A | C | C | C | I | R | C | C | C | C |
| External auditor response management | A | C | C | C | I | R | C | C | C | C |

---

## 6) Accreditation-Specific Defensibility Narrative

### 6.1 SOC 2 Type 2

Strength after Phase 3 update:

- Broader CC6/CC7 control coverage now includes ingress, model egress, loop-bound autonomy, and context admission invariants.

What must be true to claim defensibility:

- Control operation over time is evidenced (not just architecture design).
- Exception approvals and remediation SLAs are consistently enforced.

Current posture: Strong design basis with explicit enforcement scaffolding; operating-effectiveness evidence maturity still required.

### 6.2 ISO 27001

Strength after Phase 3 update:

- Control boundaries and ownership are clearer for supplier risk, operations security, and logging.

What must be true to claim defensibility:

- SoA and risk-treatment records must explicitly map to new Phase 3 control families.
- Control owner accountability and review cadence must be formalized.

Current posture: Strong technical/control model; ISMS artifacts still need completion.

### 6.3 CCPA/CPRA

Strength after Phase 3 update:

- Better data ingress/context governance reduces uncontrolled personal data processing paths.

What must be true to claim defensibility:

- Consumer rights flows must reliably map legal identity to technical run/session/memory records.
- Sensitive PI handling must be explicit in policy and runbooks.

Current posture: Improved technical posture; legal-operational workflow maturity still needed.

### 6.4 GDPR

Strength after Phase 3 update:

- Residency-aware model egress and stronger context intake controls improve Art. 25/32 defensibility.

What must be true to claim defensibility:

- DPIA/SCC gating must be operational for external processors.
- Data-subject rights execution must be end-to-end evidenced.

Current posture: Strong trajectory; transfer-governance and rights-evidence workflows remain key gaps.

### 6.5 HIPAA

Strength after Phase 3 update:

- Technical safeguards are stronger for PHI pathways due to unified ingress/model/context controls.

What must be true to claim defensibility:

- HIPAA-specific administrative/physical/technical safeguards, BAAs, training/sanction workflows, and breach operations must be fully implemented.

Current posture: Technical scaffolding is stronger (`prod_regulated_hipaa`), but legal-operational HIPAA program remains a significant gap.

---

## 7) Priority Gaps and Required Workstreams

### C-01 (Critical): HIPAA framework and evidence model are not yet integrated end-to-end

Required workstream:

- Deliver full HIPAA Security Rule crosswalk + operating evidence model + legal-operational controls.

### C-02 (High): Type 2 operating-effectiveness evidence cadence needs formal institutionalization

Required workstream:

- Define control frequencies, sample populations, owner attestations, and exception SLAs.

### C-03 (High): ISO 27001 SoA/risk-treatment artifacts need version-aligned ownership and upkeep

Required workstream:

- Tie SoA and risk-treatment artifacts directly to Phase 3 control families and owners.

### C-04 (High): Legal hold and immutable retention operations are still under-codified

Required workstream:

- Implement tested legal hold/WORM/custody procedures with recurring evidence drills.

### C-05 (Medium): Mandatory controls exist; sustained production verification and drift detection are now the gap

Required workstream:

- Prove and continuously verify no direct model calls and no unscanned context admission in production.

### C-06 (Medium): Ingress connector governance model (reference set, certification, owner responsibilities) is incomplete

Required workstream:

- Publish connector SDK/spec conformance program and assign production ownership.

### C-07 (Medium): DLP RuleOps needs recurring controlled-change lifecycle evidence

Required workstream:

- Produce recurring evidence for RBAC/SOD approvals, signing, canary outcomes, rollback readiness, and immutable audit records.

### C-08 (Medium): RLM governance requires default GA profile and policy thresholds

Required workstream:

- Set recursion/sub-call/cost limits and escalation criteria by risk tier.

### C-09 (Medium): Legal identity to technical identity linkage for DSAR and deletion remains partial

Required workstream:

- Complete rights-orchestration pipeline linking identity proofing to all technical records.

---

## 8) Production Go/No-Go Conditions for Defensible Claims

Do not claim production defensibility unless all are true:

1. RACI ownership is formally assigned with named primary/backup owners.
2. Evidence pipelines are automated, immutable where required, and periodically tested.
3. PRECINCT Gateway mediation is mandatory for model egress and ingress admission in production.
4. Context admission invariants are enforced (`no-scan-no-send`, `no-provenance-no-persist`, `no-verification-no-load`, `minimum-necessary`).
5. Legal/privacy prerequisites (DPIA, SCC, BAA where applicable) are embedded in release gates.
6. Break-glass approvals are time-boxed, reason-coded, and reviewed after use.
7. Internal audit confirms control operation, not only control design.
8. `prod_standard` and `prod_regulated_hipaa` profile controls are validated continuously.

---

## 9) Executive Positioning Statement

Phase 3 materially improves overall defensibility because it closes previously fragmented control areas without forcing framework lock-in.

Posture impact:

- Better coverage of modern agentic risk surfaces.
- Better accountability through explicit ownership and reason-coded decisions.
- Better readiness for SOC 2/ISO/GDPR/CCPA reviews.

Remaining risk is now concentrated in operating discipline and evidence maturity, plus HIPAA-specific legal-operational uplift, rather than architecture completeness.
