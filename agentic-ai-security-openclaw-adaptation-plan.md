# Agentic AI Security Reference Architecture
## OpenClaw Enterprise Adaptation Plan (Post-Phase-3, No POC Scope Drift)

Version: 1.0  
Date: 2026-02-11  
Status: Planning document (implementation deferred until POC Phase 3 completion)

---

## 1) Purpose

This document captures how we will adapt OpenClaw into the reference architecture **after** the POC reaches Phase 3.

Primary goal:
- Preserve current POC delivery focus and avoid implementation drift now.
- Define a bounded-surgery adaptation path for OpenClaw that is compatible with the Unified Agentic Security Gateway System (UASGS).

---

## 2) Scope Boundary (Explicit)

In scope now:
- Assessment capture
- Adaptation strategy
- Work package definitions
- Runtime validation plan

Out of scope now:
- Any code changes to current POC implementation
- Any code changes to OpenClaw in this phase

Decision:
- Complete POC through Phase 3 first.
- Then fork/cut a dedicated OpenClaw version and adapt it against this architecture.

---

## 3) Executive Assessment

Conclusion:
- OpenClaw is **adaptable with bounded surgery**.
- It does **not** meet enterprise baseline expectations as-is.
- A full re-engineering is not required if UASGS controls become mandatory boundaries.

High-confidence strengths already present:
- Strong gateway auth/device/origin controls
- Mature exec approval/allowlist mechanisms
- SSRF-aware fetch protection

Primary blockers for enterprise fit:
- Untrusted plugin/skill supply chain remains warn-only at install/load
- Prompt-injection safety wrappers are bypassable via dangerous toggles
- Powerful gateway-admin capabilities are available through agent tool surfaces
- Secret handling relies on local plaintext config/profile stores (permission-hardened but not cryptographically protected)
- No first-class provider governance policy for budget/quota/residency/SLO at the architecture boundary

---

## 4) Post-Phase-3 Adaptation Strategy

### 4.1 Guiding Principle

OpenClaw must run *inside* the reference architecture’s control planes, not beside them.

### 4.2 Control Plane Alignment Targets

1. LLM Plane
- Force all provider/model egress through UASGS.
- Enforce provider trust, TLS verification, residency policy, and budget policy.
- Replace direct provider credentials with reference-based credentials.

2. Context/Memory Plane
- Enforce context admission invariants before model submission.
- Require prompt-injection and safety checks for all untrusted/externally sourced context segments.
- Add deterministic audit markers for context transformations and redactions.

3. Tool Plane
- Disable direct execution of untrusted plugins/skills by default.
- Require signed/provenance-validated artifact allowlists before activation.
- Treat non-MCP interfaces (CLI/custom protocols) as first-class Tool Plane inputs.

4. Loop/Control Plane
- Keep framework-native DAG/FSM/loop semantics.
- Enforce immutable external limits at boundary: max iterations, wall-clock, token budget, action budget, escalation thresholds.
- Record reason-coded halts and policy-denied loop transitions.

5. Ingress Plane
- Standardize webhook/queue/event ingress into a common envelope and policy evaluation flow.
- Do not require gateway MITM of every protocol backend.
- Use connector model: protocol adapters normalize events, UASGS evaluates/admits, runtime consumes admitted payloads.

### 4.3 Multi-Channel Adaptation Pattern (WhatsApp, Telegram, and Similar)

This is the reference exemplar for portability:
- If this pattern works for a multi-channel consumer system like OpenClaw, it generalizes to most agentic platforms.

Design posture:
- Keep provider-specific channel integrations as edge connectors.
- Enforce a single architecture-level control boundary at UASGS ingress/egress.
- Prevent direct channel-to-agent prompt paths.

Implementation pattern:

1. Channel Edge Connector Layer
- One adapter per provider/account/region as needed.
- Responsibilities: provider auth, webhook validation/signature checks, polling/webhook handling, retries/backoff, rate limiting, provider-specific metadata capture.
- Output: normalized event envelope only.

2. Canonical Ingress Envelope
- All connectors emit the same schema:
- `source`, `provider`, `account_id`, `sender_id`, `thread_id`, `message`, `attachments`, `timestamp`, `trace_id`, `provenance`, `integrity metadata`.
- Envelope versioned for compatibility and audit replay.

3. UASGS Ingress Admission (Mandatory)
- Authenticate connector identity and source provenance.
- Validate envelope schema and freshness (anti-replay).
- Apply sender/channel ACL policy and tenancy policy.
- Run prompt-safety and DLP controls before LLM/context admission.
- Decision outcomes: allow, quarantine, deny, step-up.

4. Agent Runtime Consumption
- Agent consumes only admitted envelopes.
- Raw channel payloads are never directly interpolated into prompts.
- Context additions inherit admission verdicts and risk tags.

5. Outbound Egress Broker
- Agent emits send intents, not direct provider API calls.
- Broker enforces policy: destination allowlists, DLP/redaction, content constraints, legal/compliance restrictions, rate limits.
- Broker handles provider errors/fallback and records reason-coded delivery outcomes.

6. Cross-Channel Operational Consistency
- Same policy semantics across channels, with provider-specific exceptions explicitly declared.
- Same audit schema across channels for incident response and compliance evidence.
- Same break-glass model and approval trail across channels.

Why this matters:
- It avoids creating a provider-by-provider security architecture.
- It scales to additional channels without reworking core controls.
- It demonstrates framework/protocol independence, which is central to this reference architecture.

---

## 5) DLP and Prompt-Safety Hardening Track

Given expected enterprise and HIPAA profile requirements, this is a dedicated workstream.

### 5.1 DLP Policy Model

Support three patterns without vendor lock:
- Customer-provided DLP (existing enterprise tooling)
- Optional third-party DLP integrations
- Internal architecture-native DLP engine

Policy precedence:
1. Regulatory hard requirements (non-bypassable)
2. Tenant/org policy
3. Application policy

### 5.2 DLP Rule Lifecycle

Current reality:
- Pattern logic can be coded inline in implementations.

Required target:
- Externalized CRUD lifecycle via API/CLI
- Versioned rule sets with approvals
- Dry-run mode + enforce mode
- Full audit trail for who changed what and when
- Signed rule bundle promotion across environments

### 5.3 HIPAA-Oriented Prompt Safety

Target posture for regulated profile:
- No disallowed PHI/PII classes sent to external model providers unless policy and legal basis explicitly allow.
- Mandatory pre-LLM inspection for all new untrusted content.
- Deterministic redaction/tokenization prior to outbound prompt construction.
- Evidence-grade logging of redaction decisions (without leaking original sensitive data).

### 5.4 End-User DLP Operability

We should provide better user-facing controls:
- Rule testing interface (sample text evaluation)
- Match explainability (which rule triggered)
- False-positive suppression workflow with approval trail
- Tenant-specific override boundaries without bypassing regulatory invariants

---

## 6) Work Packages (Deferred Until Post-Phase-3)

WP1: Supply Chain Enforcement
- Signed plugin/skill verification
- Provenance checks
- Default deny for untrusted artifacts

WP2: Model Egress Governance
- UASGS-only provider access
- Credential-by-reference
- Budget/residency/SLO policy engine

WP3: Context Admission Enforcement
- Mandatory safety checks for all external/untrusted prompt segments
- Non-bypassable guardrails in regulated profiles

WP4: Tool Surface Reduction
- Remove or gate gateway-admin actions from default tool availability
- High-risk tool actions behind explicit escalation policy

WP5: DLP Rule Platform
- External CRUD API/CLI
- Versioning, approvals, and auditability
- Regulated-profile templates

WP6: Ingress Connector Standardization
- Envelope contracts for webhook/queue/event inputs
- Connector conformance tests
- Audit normalization

WP7: Runtime Trial Harness
- 3-7 day real-time run
- Fault injection + prompt injection + data exfil simulation
- Structured incident and drift reporting

---

## 7) Planned Real-Time Validation (After Adaptation)

Trial objective:
- Validate behavior under realistic multi-day operation, not only unit/integration tests.

Duration:
- Minimum 3 days, target 5-7 days.

Validation categories:
- Policy enforcement correctness
- DLP effectiveness and false-positive rate
- Model provider failover behavior (cost/perf/availability constraints)
- Loop-limit enforcement behavior under stress
- Ingress handling under malformed/adversarial events
- Audit completeness and replayability
- Cross-channel consistency (same policy intent, equivalent enforcement outcomes)
- Channel outage/error handling and outbound delivery fallback behavior

Exit criteria:
- No critical policy-bypass paths
- No unresolved high-severity data handling incidents
- Acceptable DLP precision/recall for selected profile
- Audit chain complete for all critical actions

---

## 8) Risks to Watch

1. Over-coupling to OpenClaw internals
- Mitigation: enforce architecture-level contracts at boundaries.

2. Developer bypass pressure
- Mitigation: secure-by-default SDK pathways and explicit break-glass with audit.

3. DLP usability degradation (too noisy)
- Mitigation: staged rollout (observe -> simulate -> enforce), rule analytics, targeted override process.

4. External provider operational variance
- Mitigation: policy-driven provider routing/fallback with reason-coded telemetry.

---

## 9) Final Decision Record

- We will **not** divert current POC implementation from its Phase 3 path.
- We will perform OpenClaw adaptation only after Phase 3 completion.
- Adaptation target is bounded surgery under UASGS control planes, not full rewrite.
- DLP and prompt-safety operability is a first-class post-adaptation hardening stream.
