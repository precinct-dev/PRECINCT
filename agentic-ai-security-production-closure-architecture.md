# Agentic AI Security Production Closure Architecture (v2.4 Design)

**Status:** Proposed architecture extension for implementation  
**Date:** 2026-02-13  
**Baseline:** `agentic-ai-security-reference-architecture.md` (v2.3)  
**Companion gap register:** `agentic-ai-security-production-readiness-gaps.md`

---

## 1. Design Intent

This document defines the concrete architecture needed to close the production-readiness gaps while preserving the project boundary:

1. Kubernetes-first reference implementation.
2. Portable design invariants that can be adapted to non-K8s runtimes.
3. Technical controls and machine-readable evidence as primary compliance deliverables.
4. No proprietary turnkey environment packs as a required output.

---

## 2. Non-Negotiable Invariants

These invariants apply across all deployment profiles and are the portability contract.

1. **Identity invariants**
   - All service-to-service trust uses workload identity (SPIFFE/SPIRE in reference implementation).
   - No static shared secrets for inter-service trust.
2. **Egress invariants**
   - Model/tool external egress is mediated and default-deny outside explicit allowlists.
   - No direct provider egress from agent workloads in production profiles.
3. **Artifact invariants**
   - Enforcement-critical artifacts are pinned and verified.
   - Verification failure is fail-closed for enforcement paths.
4. **Context invariants**
   - `no-scan-no-send`
   - `no-provenance-no-persist`
   - `no-verification-no-load`
   - `minimum-necessary`
5. **Audit invariants**
   - Every enforcement decision emits stable correlation IDs (`session_id`, `trace_id`, `decision_id`).
   - Audit trail is tamper-evident and exportable to immutable storage.
6. **Governance invariants**
   - Rule and connector changes are signed, versioned, reviewable, and auditable.

---

## 3. Gap-Closure Solution Architecture

## 3.1 Connector Conformance Authority (CCA)

### Purpose

Ensure ingress connectors are conformant and signed before runtime enablement.

### Components

1. **Connector Manifest Schema**
   - Connector identity
   - protocol type
   - envelope version
   - supported auth modes
   - data classification hints
   - signing metadata
2. **Connector Registry Store**
   - Versioned manifest records
   - status lifecycle (`draft`, `validated`, `approved`, `active`, `revoked`)
3. **Conformance Verifier**
   - Runs static and runtime conformance checks
   - Emits machine-readable report
4. **Runtime Registration Gate**
   - Blocks ingress from inactive/non-conformant connectors

### APIs

- `POST /v1/connectors/register`
- `POST /v1/connectors/validate`
- `POST /v1/connectors/approve`
- `POST /v1/connectors/activate`
- `POST /v1/connectors/revoke`
- `GET /v1/connectors/{id}/status`

### Portability

- **K8s:** admission policy + runtime middleware checks.
- **Compose/non-K8s:** runtime middleware checks remain mandatory; admission controls documented as unavailable and compensated by pre-deploy verification gates.

---

## 3.2 RuleOps Service (DLP + Policy Artifact Lifecycle)

### Purpose

Provide signed, governed lifecycle for rulesets and related security artifacts.

### Lifecycle

`DRAFT -> VALIDATED -> APPROVED -> SIGNED -> CANARY -> ACTIVE -> DEPRECATED -> RETIRED`

### Controls

1. RBAC and separation-of-duties role model.
2. Dual approval for high-risk rulesets.
3. Signature verification before activation.
4. Canary deployment and fast rollback.
5. Full immutable audit trail for lifecycle transitions.

### APIs

- `POST /v1/dlp/rulesets/create`
- `POST /v1/dlp/rulesets/validate`
- `POST /v1/dlp/rulesets/approve`
- `POST /v1/dlp/rulesets/sign`
- `POST /v1/dlp/rulesets/promote`
- `POST /v1/dlp/rulesets/rollback`
- `GET /v1/dlp/rulesets/active`

### Portability

- Works on any runtime; reference storage/backing may vary.
- K8s-specific admission hooks are optional portability enhancement, not dependency.

---

## 3.3 Context Admission Engine v2

### Purpose

Enforce all mandatory context invariants at gateway boundary.

### Required input contract

1. context source metadata (origin + connector id)
2. validation evidence (scanner outputs + verifier references)
3. provenance block (source URI, hash, fetch time, trust class)
4. classification and minimization metadata

### Decision outputs

- `CONTEXT_ALLOW`
- `CONTEXT_NO_SCAN_NO_SEND`
- `CONTEXT_NO_PROVENANCE_NO_PERSIST`
- `CONTEXT_NO_VERIFICATION_NO_LOAD`
- `CONTEXT_MINIMUM_NECESSARY_VIOLATION`
- `CONTEXT_PROMPT_INJECTION_UNSAFE`

### Portability

- Full logic in gateway contract layer (portable).
- K8s adds stronger network isolation; invariant enforcement does not depend on K8s primitives.

---

## 3.4 Tool Plane Governance v2

### Purpose

Move `/v1/tool/execute` from placeholder to enforced capability boundary.

### Controls

1. Capability registry v2 binding for tool execution.
2. Adapter protocol policy (`mcp`, `http`, `cli`, etc.) with allowlists.
3. Action-level authorization and argument schema validation.
4. Step-up requirement for irreversible/high-impact actions.

### Decision outputs

- `TOOL_ALLOW`
- `TOOL_CAPABILITY_DENIED`
- `TOOL_ADAPTER_UNSUPPORTED`
- `TOOL_ACTION_DENIED`
- `TOOL_STEP_UP_REQUIRED`

---

## 3.5 Loop Governor v2

### Purpose

External immutable limits for autonomous loops.

### Enforced limits

1. max steps
2. max tool calls
3. max model calls
4. max wall time
5. max egress bytes
6. max model cost
7. max provider failovers
8. max risk score

### Technical design

1. durable per-run counters
2. deterministic halting decisions
3. reason-code complete responses
4. audit correlation for every loop boundary check

---

## 3.6 Approval Capability Service

### Purpose

Replace approval stub with secure, bounded approval flow.

### Model

1. Approval requests are signed decision intents.
2. Approvals mint short-lived capability tokens bound to:
   - actor identity
   - action/tool scope
   - session/run ID
   - expiration
3. Tokens are one-time or bounded-use.

### Audit

Mandatory events:

- `approval.requested`
- `approval.granted`
- `approval.denied`
- `approval.consumed`
- `approval.expired`

---

## 3.7 Break-Glass Control Plane

### Purpose

Provide emergency override path that is bounded and fully auditable.

### Controls

1. dual-authorization for activation
2. strict TTL
3. scoped override boundaries
4. automatic reversion
5. mandatory elevated audit marker and incident ID linkage

---

## 3.8 Enforcement Profiles Engine

### Purpose

Materialize `dev`, `prod_standard`, and `prod_regulated_hipaa` as enforceable bundles.

### Features

1. profile-specific policy packs
2. startup conformance checks
3. explicit fail-start on incompatible profile/runtime config
4. machine-readable profile manifest outputs

---

## 3.9 Conformance Suite Framework

### Purpose

Gate production claims on objective conformance results.

### Suites

1. policy conformance
2. connector conformance
3. RuleOps lifecycle conformance
4. profile conformance (`prod_standard`, `prod_regulated_hipaa`)
5. audit/evidence conformance

### Output

Signed machine-readable conformance bundle:

- JSON report
- control IDs
- test IDs
- pass/fail with timestamps and artifact references

---

## 3.10 Audit and Evidence Fabric v2

### Purpose

Make technical evidence auditor-ready, machine-readable, and exportable.

### Deliverables

1. **Evidence graph model** linking:
   - control -> test -> runtime event -> artifact
2. **Machine-readable exports**
   - JSON and CSV control evidence bundles
   - immutable audit chain export manifests
3. **Traceability guarantees**
   - stable IDs
   - reproducible extraction queries
   - schema versioning

### Scope boundary

This is technical evidence generation and packaging. Organization process governance remains out-of-scope.

---

## 3.11 Model Trust and Artifact Integrity v2

### Purpose

Close high-assurance gaps in provider trust and model artifact control.

### Controls

1. signed provider catalog with version pinning
2. strict endpoint trust policy (TLS identity constraints)
3. DNS integrity policy module and drift alerts
4. guard-model artifact digest/signature verification at startup
5. fail-closed enforcement for compromised enforcement-critical artifacts

---

## 3.12 Non-K8s Adaptation Guide (No Turnkey Pack)

### Purpose

Provide safe adaptation path to runtimes like ECS/Fargate/GCP cloud containers without shipping proprietary turnkey stacks.

### Contents

1. invariant-to-runtime mapping matrix
2. minimum compensating controls when K8s primitives are absent
3. verification checklist against go/no-go invariants
4. common misconfiguration anti-patterns

---

## 3.13 Use-Case-Specific Technical Extensions

## OpenClaw Port

1. enforce model mediation by default
2. ingress connector wrapping and conformance registration
3. direct-network tool disablement/replacement via governed tool plane
4. context/memory admission wrappers
5. bounded loop integration and evidence generation

## Neuro-Symbolic CSV Fact Ingestion

1. dedicated context fetcher/ingestion tool with quarantine
2. schema + content validation pipeline for CSV
3. provenance hashing and handle-based context references
4. admission-gated fact persistence

---

## 4. Kubernetes-First + Compose Portability Rules

1. Implement in Kubernetes first for production-grade controls.
2. Port to Compose where controls do not require K8s-only primitives.
3. For controls requiring K8s primitives:
   - keep control in K8s reference implementation
   - document Compose limitation and compensating technical checks
4. Never weaken portability-invariant controls when porting.

---

## 5. Updated Reference Contracts (Canonical Set)

Canonical endpoint set for v2.4:

- `POST /v1/ingress/submit`
- `POST /v1/context/admit`
- `POST /v1/model/call`
- `POST /v1/tool/execute`
- `POST /v1/loop/check`
- `POST /v1/dlp/rulesets/*` (lifecycle)
- `POST /v1/connectors/*` (lifecycle)
- `POST /v1/approval/*`
- `POST /v1/breakglass/*`

Canonical reason-code catalog:

1. published as versioned schema artifact
2. enforced in CI conformance tests
3. shared by SDKs and docs

---

## 6. Compliance-Oriented Technical Evidence Model

## 6.1 Output formats

1. JSON (primary machine-readable)
2. CSV (auditor ingestion)
3. XLSX/PDF summaries (human-readable)

## 6.2 Evidence object minimum fields

1. `control_id`
2. `control_statement`
3. `evidence_type`
4. `evidence_source`
5. `evidence_timestamp`
6. `verification_status`
7. `artifact_ref`
8. `trace/session/decision refs` where applicable

## 6.3 Control-to-evidence traceability

Every technical control must map to:

1. enforcement mechanism,
2. runtime/test evidence extractor,
3. conformance assertion.

---

## 7. Roadmap Integration (v2.4)

## Stage A: Contract + Core Governance

1. canonical contracts and reason codes
2. Connector Conformance Authority
3. RuleOps lifecycle
4. approval + break-glass

## Stage B: Plane Completion

1. context invariants v2
2. tool plane v2
3. loop governor v2
4. profile engine

## Stage C: Evidence and Compliance Technical Expansion

1. evidence graph model and exports
2. technical control library expansion for table-stakes frameworks
3. PCI/HIPAA technical profile packs

## Stage D: Use-Case Delivery

1. OpenClaw secure port
2. Neuro-symbolic ingestion hardening
3. biotech adaptation guidance (K8s baseline + non-K8s mapping)

---

## 8. Definition of Done for Architecture Upgrade

The architecture is considered upgraded when:

1. All solution components in Section 3 are specified in normative terms.
2. Canonical contracts and reason-code catalog are frozen and versioned.
3. Kubernetes-first implementation path is explicit.
4. Compose portability boundaries are explicit for each component.
5. Technical evidence model supports machine-readable auditor consumption.

