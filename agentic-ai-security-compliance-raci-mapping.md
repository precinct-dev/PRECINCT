# Agentic AI Security Reference Architecture
## Compliance Crosswalk + RACI Operating Model (Production)

Document version: 1.0  
Date: 2026-02-11  
Audience: Audit, legal, privacy, risk, security leadership, platform operations

---

## 1) Purpose

This document shows how the reference architecture can be defended for enterprise accreditation and regulatory review when deployed in production on a leading cloud provider and/or managed Kubernetes environment.

It provides:

- A control-family crosswalk to SOC 2 Type 2, ISO 27001, CCPA/CPRA, GDPR, and HIPAA
- A RACI operating model for core responsibilities across security, engineering, legal, privacy, and risk roles
- A gap statement highlighting where additional governance/process controls are required

This is an architecture and operating-model mapping, not legal advice.

The intended operating stance is the 3 Rs:
- Repair (self-heal and recover),
- Rotate (short-lived identity and secret references),
- Repave (rebuild trusted runtime state on demand).

---

## 2) Roles Used in RACI

- CISO: Executive accountability for security posture and risk acceptance.
- Security Architecture: Security design authority and control design owner.
- Platform Engineering: Kubernetes/cloud platform build and hardening owner.
- SRE/Operations: Runtime reliability, observability, incident operations.
- Application/Agent Engineering: Agent/tool integration teams using the platform.
- GRC/Compliance: Control library ownership, testing cadence, audit coordination.
- Privacy Office/DPO: Privacy-by-design, DSAR and cross-border governance owner.
- Legal Counsel: Contractual and regulatory interpretation (BAA, SCC, DPA, notification).
- Internal Audit: Independent control testing and assurance.
- Security Operations (SecOps/IR): Monitoring, detection, triage, and incident handling.

---

## 3) Control-Family Crosswalk (Architecture to Accreditation)

Legend:
- Implemented: technical capability exists in architecture and repository artifacts
- Partial: capability exists but needs organizational process or operating evidence to be audit-defensible
- Gap: material missing control or ownership/evidence path

| Control Family | Architecture Mechanism | SOC 2 Type 2 | ISO 27001 | CCPA/CPRA | GDPR | HIPAA | Status |
|---|---|---|---|---|---|---|---|
| Workload identity and strong auth | SPIFFE/SPIRE SVIDs + mTLS enforcement | CC6.1, CC6.7 | Access control, network security, cryptography controls | Reasonable security baseline | Art. 32 | 164.312(d), 164.312(e)(1) | Implemented |
| Policy-based authorization and least privilege | OPA policy engine + tool grants + path/destination controls | CC6.1, CC6.6 | Access control and privileged access controls | Access minimization expectation | Art. 25, Art. 32 | 164.312(a)(1), 164.308(a)(4) | Implemented |
| Secret protection and non-exfiltration pattern | Late-binding SPIKE token substitution | CC6.1, CC6.7 | Cryptography and secret management controls | Security of personal info | Art. 32 | 164.312(a), 164.312(c)(1) | Implemented |
| Data loss/exfiltration controls | DLP, response firewall, step-up gating, exfiltration rules | CC6.6, CC7.1 | Monitoring and data protection controls | 1798.150 risk reduction posture | Art. 25, Art. 32 | 164.312(c)(1), 164.308(a)(1) | Partial |
| LLM provider egress governance | Gateway-mediated model API access, provider allowlists, endpoint trust policy, residency enforcement | CC6.6, CC7.2 | Supplier/network/data transfer controls | Service provider controls expectation | Art. 28, Art. 44+, Art. 32 | 164.308(b)(1), 164.312(e)(1) | Gap |
| Auditability and evidence chain | Structured audit logs + hash chain + trace correlation | CC7.2 | Logging and monitoring controls | Accountability and consumer rights support | Art. 30, Art. 5(2) | 164.312(b), 164.316(b)(1) | Partial |
| DLP rule lifecycle governance | Rule CRUD controls, change approvals, versioning, and rollback for DLP patterns | CC6.7, CC7.2 | Change management and logging controls | Security safeguards expectation | Art. 24, Art. 32 | 164.308(a)(1), 164.316(b)(1) | Gap |
| Supply-chain integrity | Image signature + digest admission policies; signed registry reload path | CC6.7, CC7.1 | Secure development and change controls | Security safeguards expectation | Art. 32 | 164.308(a)(1), 164.312(c)(1) | Partial |
| Privacy rights operations | GDPR delete workflow + session retention + ROPA | CC6/CC7 support controls | Information lifecycle and retention controls | 1798.105 deletion, CPRA sensitive PI handling | Art. 17, Art. 30 | 164.316 policies/procedures support | Partial |
| Incident response and legal response | Alerting + audit explain/search + response playbooks (emerging) | CC7.x monitoring/response | Incident management controls | Breach response obligations | Art. 33/34 support | 164.308(a)(6) | Partial |
| Third-party/processor governance | External scan providers optional and documented | CC9 vendor risk context | Supplier relationship controls | Service provider obligations | Art. 28, Art. 44+ | 164.308(b)(1) | Gap |
| Business continuity and resilience | Circuit breakers, rate limiting, deployment profiles | Availability criteria | Continuity and resilience controls | Service reliability implication | Art. 32(1)(b) | 164.308(a)(7) | Partial |

---

## 4) RACI Matrix - Security and Compliance Operations

### 4.1 Core Security Control Lifecycle

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| Threat model baseline (STRIDE/PASTA) | A | R | C | C | C | C | C | C | C | I |
| OPA policy design and updates | I | A/R | C | C | C | C | I | I | C | I |
| Tool and UI registry governance | I | A | R | C | C | C | I | I | C | I |
| Identity and mTLS posture management | I | A | R | R | I | I | I | I | C | I |
| Secrets/token substitution controls | I | A | R | R | C | I | I | I | C | I |
| LLM provider egress policy and endpoint trust controls | I | A | R | R | C | C | C | C | C | I |
| Supply-chain admission policy (signatures/digests) | I | A | R | C | I | C | I | I | C | I |
| Runtime monitoring and alert triage | I | C | C | R | I | I | I | I | A/R | I |
| Incident handling and containment | A | C | C | R | C | I | C | C | A/R | I |
| Control evidence collection package | I | C | C | C | I | A/R | C | C | C | I |
| Formal risk acceptance/exception approval | A/R | C | C | C | I | C | C | C | C | I |

### 4.2 Privacy, Legal, and Regulated Data Workflow

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| Data classification model and tagging policy | I | C | I | I | C | C | A/R | C | I | I |
| GDPR/CCPA/CPRA deletion workflow operations | I | C | C | R | I | C | A/R | C | I | I |
| ROPA maintenance and processing records | I | I | I | I | I | C | A/R | C | I | I |
| Cross-border transfer controls (SCC/DPIA) | I | C | C | I | I | C | A/R | A/R | I | I |
| HIPAA applicability and BAA governance | C | C | I | I | I | C | C | A/R | I | I |
| Subpoena/eDiscovery legal hold activation | I | I | C | R | I | C | C | A/R | C | I |

### 4.3 Accreditation Readiness and Audit Cadence

| Process | CISO | Security Architecture | Platform Engineering | SRE/Operations | App/Agent Engineering | GRC/Compliance | Privacy Office/DPO | Legal Counsel | SecOps/IR | Internal Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| SOC 2 Type 2 evidence period planning | A | C | C | C | I | R | I | C | C | C |
| ISO 27001 SoA and risk treatment alignment | A | C | C | C | I | R | C | C | C | C |
| Control testing and remediation tracking | I | C | R | R | C | A | I | I | C | C |
| Pre-audit readiness review | A | C | C | C | I | R | C | C | C | C |
| External auditor response management | A | C | C | C | I | R | C | C | C | C |

---

## 5) Accreditation-Specific Defensibility Narrative

### 5.1 SOC 2 Type 2

Strengths:
- Strong technical controls around access, change integrity, and monitoring.
- Structured and tamper-evident audit evidence foundation.

What must be true to pass Type 2 defensibly:
- Operating effectiveness evidence across the audit period (not just design).
- Exception management and remediation SLAs demonstrated consistently.

Current posture: Defensible design; operating-evidence program still maturing.

### 5.2 ISO 27001

Strengths:
- Clear architecture controls for access, logging, network security, and cryptography.
- Policy-driven enforcement model with documented risk controls.

What must be true to pass defensibly:
- Formal Statement of Applicability (SoA), risk treatment plan, and control owner accountability.
- Clear mapping to current ISO 27001 version and Annex A control set in use.

Current posture: Defensible technical basis; ISMS governance artifacts require completion.

### 5.3 CCPA/CPRA

Strengths:
- Session retention/deletion mechanisms and processing documentation exist.
- Security controls reduce unauthorized access and data leakage risk.

What must be true to pass defensibly:
- Consumer request workflows mapped from legal identity to technical identifiers.
- CPRA-sensitive personal information handling policy integrated into operations.

Current posture: Technically promising; legal-operational workflows need stronger productization.

### 5.4 GDPR

Strengths:
- ROPA document and technical deletion workflow are present.
- Data minimization and pseudonymous identity approach is explicit.

What must be true to pass defensibly:
- DPIA/SCC gating for any optional external processing paths.
- Data subject rights execution and evidencing tied to natural-person identity workflow.

Current posture: Strong foundational controls with known legal/operational gaps.

### 5.5 HIPAA

Strengths:
- Security architecture provides meaningful safeguards relevant to HIPAA Security Rule technical controls.

What must be true to pass defensibly:
- HIPAA-specific policy set (administrative, physical, technical safeguards), BAAs, sanction/training procedures, and breach workflow.
- PHI data-flow inventory and minimum-necessary enforcement guidance.

Current posture: Significant gap; needs dedicated HIPAA compliance workstream before asserting readiness.

---

## 6) Priority Gaps and Required Workstreams

### C-01 (Critical): HIPAA control framework and evidence model not yet integrated

Required workstream:
- Publish HIPAA Security Rule crosswalk (45 CFR 164.308/310/312/314/316) to architecture controls and operating evidence.

### C-02 (High): Type 2 operating-effectiveness evidence pipeline needs formal cadence

Required workstream:
- Define control frequency, sample population, control owner attestations, and exception SLAs for SOC 2 evidence period.

### C-03 (High): ISO 27001 SoA/Risk Treatment artifacts need explicit ownership and version alignment

Required workstream:
- Produce SoA, control applicability rationale, and risk treatment tracking tied to architecture controls.

### C-04 (High): Legal hold and immutable retention operations not fully codified

Required workstream:
- Implement tested legal hold, WORM retention, custody controls, and evidence of execution drills.

### C-05 (Medium): CPRA and GDPR rights execution must bind legal identities to SPIFFE/technical identities

Required workstream:
- Build DSAR/deletion orchestration that links identity proofing to all affected technical records.

### C-06 (Medium): Third-party and cross-border controls for optional external scanning paths are policy-dependent

Required workstream:
- Enforce policy guardrail that disallows external inference/scanning unless legal prerequisites are approved and recorded.

### C-07 (Medium): DLP rule CRUD governance is not yet codified as a controlled change process

Required workstream:
- Define DLP rule management controls (RBAC, approval workflow, signed versions, validation gates, staged rollout, rollback, and immutable change audit).

### C-08 (High): External LLM provider governance is not yet implemented as a mandatory mediated path

Required workstream:
- Require model-provider traffic through a governed gateway path with secret references, endpoint identity policy, DNS integrity checks, region/residency gates, and auditable provider allowlists.

---

## 7) Production Go/No-Go Conditions for Defensible Claims

Do not claim production defensibility for the listed accreditations unless all conditions below are met:

1. RACI ownership is formally assigned in operating procedures (names, backups, escalation chain).
2. Control evidence pipelines are automated, immutable where required, and routinely validated.
3. Legal/privacy prerequisites (DPIA, SCC, BAA where applicable) are integrated into deployment gates.
4. Break-glass and exception approvals are time-boxed and reviewed post-event.
5. Periodic internal audit testing demonstrates control operation, not only control design.

---

## 8) Executive Positioning Statement

This architecture is credible to present to auditors, legal, and risk stakeholders as a defensible production security foundation because it already centralizes identity, policy enforcement, secret handling, exfiltration controls, and auditability.

The remaining work is primarily governance operationalization and accreditation packaging, not a full re-architecture. In practical terms:

- SOC 2 Type 2 / ISO 27001 / GDPR / CCPA-CPRA: achievable with focused evidence and governance hardening.
- HIPAA: feasible but currently requires a dedicated control and legal-operational uplift before asserting readiness.
