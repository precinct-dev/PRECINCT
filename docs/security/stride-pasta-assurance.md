# PRECINCT
## STRIDE + PASTA Assurance Mapping (Production Profile)

PRECINCT -- Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools

Document version: 1.3
Date: 2026-03-07
Audience: Security architecture, audit, legal, risk, platform leadership

---

## 1) Purpose and Scope

This document maps the reference architecture to:

- STRIDE (threat-class coverage)
- PASTA (risk lifecycle coverage)

It incorporates the approved **Phase 3 architectural direction** centered on the **PRECINCT Gateway** and this document now reflects the latest hardening pass intended to close architecture-level (non-operational) gaps.

Deployment scope assumed:

- Leading cloud provider and/or
- Properly managed Kubernetes environment

This is an assurance mapping, not legal advice or an attestation.

---

## 2) Assumptions for Production Defensibility

Defensibility statements in this document assume:

1. Workload identity is SPIFFE/SPIRE based and mTLS is enforced.
2. PRECINCT Gateway is the mandatory policy boundary for ingress admission, model egress, tool execution, and governed memory I/O.
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

- `docs/architecture/reference-architecture.md`
- `docs/architecture/production-closure.md`

Representative implementation evidence:

- Tool registry verification and poisoning checks: `internal/gateway/middleware/tool_registry.go`
- Step-up gating and risk scoring: `internal/gateway/middleware/step_up_gating.go`
- Response firewall and handle-ization: `internal/gateway/middleware/response_firewall.go`
- DLP scanner: `internal/gateway/middleware/dlp.go`
- OPA authorization policies: `config/opa/mcp_policy.rego`
- Exfiltration rules: `config/opa/exfiltration.rego`
- Audit hash chain and verification: `internal/gateway/middleware/audit.go`, `internal/gateway/middleware/audit_verify.go`
- K8s admission for signed/digest-pinned images: `deploy/terraform/admission/constraints/enforce-image-signature.yaml`, `deploy/terraform/admission/constraints/enforce-image-digest.yaml`
- Compliance taxonomy and generator: `tools/compliance/control_taxonomy.yaml`, `tools/compliance/generate.py`
- GDPR ROPA and deletion workflow: `docs/compliance/gdpr-article-30-ropa.md`, `internal/gateway/middleware/gdpr_delete.go`
- Channel mediation (Ed25519 webhook verification): `internal/gateway/middleware/dlp.go`, `internal/gateway/middleware/deep_scan.go`
- Data source integrity (hash verification): `internal/gateway/middleware/tool_registry.go`, DataSourceDefinition struct
- Escalation detection and scoring: `internal/gateway/middleware/session_context.go`, EscalationScore formula
- Principal hierarchy (SPIFFE-to-role): `internal/gateway/middleware/spiffe_auth.go`, X-Precinct-Principal-Level header
- Irreversibility gating: `internal/gateway/middleware/step_up_gating.go`, ClassifyActionDestructiveness taxonomy
- External threat validation: Shapira et al. (2026), *Agents of Chaos*, arXiv:2602.20021v1

Phase 3 implemented controls (all in `internal/gateway/`):

- **RLM Governance Engine**: `phase3_rlm.go` -- per-lineage state tracking, subcall budget enforcement, depth limits, UASGS bypass prevention
- **Loop Governor State Machine**: `phase3_loop_plane.go` -- 8-state governance machine, all 8 immutable limits, operator halt, approval flow
- **Loop Admin API**: `admin_phase3.go` -- per-run detail, operator halt endpoint, audit logging for all admin operations
- **Context Memory Tiering**: `phase3_runtime_helpers.go` (`evaluateContextInvariants`) -- ephemeral/session/long_term/regulated tiers with DLP enforcement
- **CLI Tool Adapter**: `phase3_plane_stubs.go` (`toolPlanePolicyEngine`) -- shell injection prevention via command allowlists, max-args, denied-arg-token detection
- **Ingress Connector Envelope**: `phase3_ingress_plane.go` -- canonical parsing, SPIFFE source principal authentication, SHA256 content-addressing, replay detection with 30min nonce TTL
- **Phase 3 Contracts**: `phase3_contracts.go` -- `PlaneRequestV2`, `PlaneDecisionV2`, `RunEnvelope`, `AuditEventV2` with full reason code taxonomy
- **Go SDK SPIKE Token Builder**: `sdk/go/mcpgateway/spike_token.go` -- `BuildSPIKETokenRef`, `BuildSPIKETokenRefWithScope`
- **Python SDK Runtime**: `sdk/python/mcp_gateway_sdk/runtime.py` -- `build_spike_token_ref`, `resolve_model_api_key_ref`, DSPy gateway LM configuration

---

## 4) Posture Delta From Phase 3 Architecture

This section captures the impact of the Phase 3 proposal itself (design-level uplift). Implementation evidence for these controls is still required before final auditor claims.

| Control Plane | Pre-Phase 3 Posture | Phase 3 Implementation Status | Net Effect |
|---|---|---|---|
| LLM egress | Fragmented, app-specific provider handling | **Implemented:** Gateway-mediated provider governance, trust checks, residency + budget policy, provider fallback, prompt safety, RLM governance integration | Major uplift in disclosure, supplier, and audit defensibility |
| Loop control | Inconsistent per framework | **Implemented:** Full 8-state governance machine, all 8 immutable limits, operator halt via admin API, approval flow, audit logging | Strong DoS/EoP resilience without framework lock-in |
| Ingress | Not first-class across webhook/queue/schedule | **Implemented:** Canonical connector envelope with source principal auth, SHA256 content-addressing, replay detection (30min nonce TTL), freshness validation (10min window) | Strong spoofing/tampering coverage for event-driven agents |
| Context engineering | Detection-oriented, uneven enforcement | **Implemented:** All 4 invariants + memory tiering (ephemeral/session/long_term/regulated) with DLP enforcement and step-up for regulated reads | Large uplift in prompt-injection and data handling consistency |
| RLM/repl flows | Largely ungoverned pattern | **Implemented:** Per-lineage governance engine with depth/subcall/budget limits and UASGS bypass prevention | Reduced emerging-runtime risk and better auditability |
| DLP control plane | Static or ad hoc rule lifecycle | **Implemented:** Full RuleOps lifecycle (create/validate/approve/sign/promote/rollback) via admin API with immutable audit | Closes major tampering gap for rule CRUD |
| Tool plane | Placeholder with minimal enforcement | **Implemented:** Capability registry v2, multi-protocol adapters (MCP/HTTP/CLI/email/Discord), CLI shell injection prevention, step-up for high-risk actions | Closes enforcement gap for tool execution boundary |
| HIPAA prompt safety | Implicit/partial handling | **Implemented:** Regulated profile with deny/tokenize defaults and minimum-necessary controls | Closes core architecture gap for prompt-bound PHI/PII handling |

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
- PRECINCT Gateway endpoint trust policy for model egress
- Production default for mediated model egress (policy + identity + network gates)
- Ingress canonical connector envelope with source principal authentication (source_principal must match ActorSPIFFEID)
- Replay detection with composite nonce key and 30-minute TTL
- Freshness validation with 10-minute past/future window

Coverage rating:

- Current: High
- Target with operational maturity: Very High

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
- PRECINCT Gateway unified audit taxonomy v2 across ingress/model/tool/memory/loop/RLM/context-admission

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
- Memory tier leakage across classification boundaries

Controls:

- Late-binding secret substitution and referential credentials
- DLP and response firewall
- Model-provider residency and endpoint policy gates
- Mandatory context admission controls (all four invariants implemented):
  - no-scan-no-send
  - no-provenance-no-persist
  - no-verification-no-load
  - minimum-necessary (DLP classification + tokenize/redact for sensitive content)
- Context memory tiering: long_term writes require `dlp_classification=clean`; regulated tier reads require step-up
- HIPAA prompt safety profile with deny/tokenize defaults and minimum-necessary preprocessing
- Ingress payload content-addressing: SHA256 references replace raw payloads in responses (`ingress://payload/<hex>`)

Coverage rating:

- Current: High (upgraded from conditional; all four context invariants and memory tier governance now implemented)
- Target with operational maturity: Very High

Residual gaps:

- High-risk fail-closed defaults now exist in architecture; remaining work is operational verification.
- Legal prerequisites for external processors (DPIA/SCC/contract terms) remain organizational dependencies.

### 5.5 Denial of Service (D)

Threat focus:

- Runaway loops
- Provider outages and budget exhaustion
- Gateway/connector bottlenecks
- RLM recursive cost explosions

Controls:

- Rate limits, request limits, and circuit breakers
- Loop governor with full 8-state machine and all 8 immutable limits (max_steps, max_tool_calls, max_model_calls, max_wall_time_ms, max_egress_bytes, max_model_cost_usd, max_provider_failovers, max_risk_score)
- Provider fallback policy and explicit halt reason codes (15 distinct loop reason codes)
- Operator halt via admin API (`POST /admin/loop/runs/<id>/halt`)
- RLM governance engine with per-lineage subcall budgets and depth limits
- Ingress replay detection with 30-minute nonce TTL prevents replay-driven resource exhaustion

Coverage rating:

- Current: High (upgraded from Medium-High; loop governor and RLM governance now implemented)
- Target with operational maturity: Very High

Residual gaps:

- Formal HA/SLO evidence package and failure-injection cadence are not yet audit-packaged.
- Multi-region DR/RTO/RPO validation remains to be codified as repeatable evidence.

### 5.6 Elevation of Privilege (E)

Threat focus:

- Prompt injection driving privilege jumps
- Hidden sub-call escalation in RLM/REPL workflows
- Cross-plane policy bypass attempts
- Shell injection via CLI tool adapter

Controls:

- OPA least-privilege policy for capabilities
- Step-up gating and risk scoring
- Loop governor with full 8-state machine, immutable limits, and operator halt
- RLM governance engine with UASGS bypass prevention (`RLM_BYPASS_DENIED` for unmediated subcalls), per-lineage depth limits, and subcall budgets
- Tool plane capability registry v2 with action-level authorization
- CLI tool adapter with shell injection prevention (command allowlists, denied-arg-token detection for `;`, `&&`, `||`, `|`, `$(`, `` ` ``, `>`, `<`)
- Context memory tier governance (regulated tier reads require step-up)

Coverage rating:

- Current: Very High (upgraded from High; RLM bypass prevention, CLI shell injection prevention, and memory tier governance now implemented)
- Target with operational maturity: Very High

Residual gaps:

- JIT approval workflow and reviewer-accountability controls need standardized implementation.
- Delegation-chain modeling for complex multi-agent subject/actor flows needs maturity.

### 5.7 New Controls (Agents of Chaos Threat Validation)

The following five controls were added to address threat patterns validated by the Agents of Chaos paper (Shapira et al., 2026, arXiv:2602.20021v1), which documents 16 case studies of real-world agentic AI attacks.

#### 5.7.1 Channel Mediation

Threat addressed: Prompt injection via unmediated channels (Case Study #3, #4, #5); unbounded resource consumption.

Controls:

- Ed25519 webhook signature verification for all inbound event channels
- Message content routing through middleware pipeline (DLP step 7 + deep scan step 10)
- All external channel content treated as untrusted and scanned before agent ingestion

STRIDE mapping: Information Disclosure, Denial of Service

#### 5.7.2 Data Source Integrity

Threat addressed: External data poisoning and rug-pull attacks (Case Study #10); mutable data sources changing after initial verification.

Controls:

- Hash verification per DataSourceDefinition struct at tool registry level (middleware step 5)
- MutablePolicy enforcement: data sources declare mutability; mutable sources trigger re-verification on each access
- Digest logging for all external data fetches

STRIDE mapping: Tampering

#### 5.7.3 Escalation Detection

Threat addressed: Progressive concession accumulation (Case Study #7); gradual privilege escalation through repeated benign-appearing requests.

Controls:

- EscalationScore formula: Impact x (4 - Reversibility)
- Three-tier threshold system: Warning=15, Critical=25, Emergency=40
- RecordEscalation() tracks cumulative session score in middleware step 8 (session context)
- Threshold breaches trigger alerts and automatic policy tightening

STRIDE mapping: Elevation of Privilege

#### 5.7.4 Principal Hierarchy

Threat addressed: Identity spoofing via authority confusion (Case Study #8); agent impersonating higher-privilege principals.

Controls:

- SPIFFE-to-role resolution in middleware step 3 (SPIFFE auth)
- X-Precinct-Principal-Level metadata enrichment header injected by gateway
- OPA policy decisions incorporate principal level for least-privilege enforcement
- Role hierarchy prevents lateral or vertical movement without explicit attestation

STRIDE mapping: Spoofing, Elevation of Privilege

#### 5.7.5 Irreversibility Gating

Threat addressed: Progressive destruction (Case Study #1); agents executing irreversible actions without adequate oversight.

Controls:

- ClassifyActionDestructiveness taxonomy categorizes actions by reversibility
- Automatic step-up authentication required for critical/irreversible action classifications (middleware step 9)
- Actions classified as irreversible require human-in-the-loop approval or elevated capability token
- Audit log records destructiveness classification and gating decision for every action

STRIDE mapping: Elevation of Privilege

---

## 6) STRIDE Coverage Summary

| STRIDE Element | Current Coverage | Target Coverage (Operational Maturity) | Main Remaining Gap |
|---|---|---|---|
| Spoofing | High | Very High | Uniform attestation + connector governance operations |
| Tampering | High | Very High | Operating-evidence maturity for RuleOps and artifact enforcement |
| Repudiation | High | Very High | Immutable retention/legal hold execution rigor |
| Info Disclosure | High | Very High | Legal transfer prerequisites + profile verification evidence |
| DoS | High | Very High | Audit-ready resilience/DR evidence packages |
| Elevation of Privilege | Very High | Very High | JIT approvals + delegation-chain rigor |

---

## 7) PASTA Mapping to Architecture

### Stage 1: Define Business and Security Objectives

Assessment: Strong

Phase 3 effect:

- Explicit objectives now include model egress governance, ingress governance, context admission invariants, and loop-bound autonomy controls.

### Stage 2: Define Technical Scope

Assessment: Strong

Phase 3 effect:

- Scope now explicitly covers five agentic planes plus policy/audit/identity/secrets planes under one PRECINCT Gateway contract.

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

| PASTA Stage | Current | With Phase 3 Implemented | Remaining Gap |
|---|---|---|---|
| Stage 1 Objectives | Strong | Strong | None material |
| Stage 2 Scope | Strong | Strong (all 5 planes implemented) | None material |
| Stage 3 Decomposition | Strong | Strong (clear subsystem boundaries with implemented contracts) | None material |
| Stage 4 Threat Analysis | Strong | Strong (RLM bypass, shell injection, replay, memory tier threats covered) | Keep updating threat library |
| Stage 5 Vulnerability Analysis | Medium-High | High (implemented controls reduce attack surface) | Continuous evidence and metrics maturity |
| Stage 6 Attack Modeling | Medium-High | High (loop stress, RLM recursion, ingress replay, CLI injection now testable) | Formal adversary-emulation cadence |
| Stage 7 Risk/Impact | Medium-High | High (reason-code-complete decisions enable precise risk treatment) | Executive risk acceptance operationalization |

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

Overall posture is significantly stronger because Phase 3 controls are now **implemented**, not merely designed:

- **Model egress**: mandatory mediation with provider governance, trust policy, residency, budget/fallback, prompt safety, and RLM governance integration.
- **Event ingress**: canonical connector envelope with source principal authentication, SHA256 content-addressing, replay detection (30min nonce TTL), and freshness validation (10min window).
- **Loop autonomy bounds**: full 8-state governance machine with all 8 immutable limits, operator halt via admin API, and approval flow.
- **Context admission**: all four invariants enforced plus context memory tiering (ephemeral/session/long_term/regulated) with DLP enforcement.
- **RLM execution**: per-lineage governance with depth/subcall/budget limits and UASGS bypass prevention.
- **Tool execution**: capability registry v2 with multi-protocol adapters and CLI shell injection prevention.

What remains is operating-evidence maturity and legal-operational governance, not architecture or implementation deficiency.

Practical readout:

- SOC 2 Type 2 / ISO 27001 / GDPR / CCPA-CPRA: defensible trajectory with focused evidence hardening. Technical controls are implemented.
- HIPAA: technical safeguards are implemented (`prod_regulated_hipaa`); legal-operational uplift still required before readiness claims.
