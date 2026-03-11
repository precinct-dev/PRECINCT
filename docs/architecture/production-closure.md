# PRECINCT Production Closure Architecture (v2.4 Design)

PRECINCT -- Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools

**Status:** Proposed architecture extension for implementation  
**Date:** 2026-02-13  
**Baseline:** `precinct-reference-architecture.md` (v2.3)  
**Companion gap register:** `precinct-production-readiness-gaps.md`

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
   - Any indexed evidence backend (for example OpenSearch) uses secret-managed credentials/certificates, encrypted transport (TLS/mTLS), and identity-bound access controls.
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

### Status: IMPLEMENTED

The context admission engine is fully implemented in `evaluateContextInvariants()` (`POC/internal/gateway/phase3_runtime_helpers.go`). All four invariants are enforced, plus context memory tiering.

### Required input contract

1. context source metadata (origin + connector id)
2. validation evidence (scanner outputs + verifier references)
3. provenance block (source URI, hash, fetch time, trust class)
4. classification and minimization metadata
5. memory tier classification (ephemeral/session/long_term/regulated)

### Decision outputs

- `CONTEXT_ALLOW`
- `CONTEXT_SCHEMA_INVALID` (invalid memory tier)
- `CONTEXT_NO_SCAN_NO_SEND`
- `CONTEXT_PROMPT_INJECTION_UNSAFE`
- `CONTEXT_DLP_CLASSIFICATION_REQUIRED`
- `CONTEXT_DLP_CLASSIFICATION_DENIED`
- `CONTEXT_MEMORY_READ_STEP_UP_REQUIRED` (regulated tier read)
- `CONTEXT_MEMORY_WRITE_DENIED` (long_term write without clean DLP, or missing provenance)

### Memory tier governance

- `ephemeral`: default tier, no additional restrictions
- `session`: standard validation applies
- `long_term`: writes require `dlp_classification=clean`
- `regulated`: reads require step-up approval (DecisionStepUp)

### Portability

- Full logic in gateway contract layer (portable).
- K8s adds stronger network isolation; invariant enforcement does not depend on K8s primitives.

---

## 3.4 Tool Plane Governance v2

### Purpose

Move `/v1/tool/execute` from placeholder to enforced capability boundary.

### Status: IMPLEMENTED

The tool plane governance engine is fully implemented in `toolPlanePolicyEngine` (`POC/internal/gateway/phase3_plane_stubs.go`).

### Controls

1. Capability registry v2 binding for tool execution (YAML-configurable via `capabilityRegistryV2` schema).
2. Adapter protocol policy (`mcp`, `http`, `cli`, `email`, `discord`) with per-capability allowlists.
3. Action-level authorization with resource matching and per-action tool allowlists.
4. Step-up requirement for irreversible/high-impact actions (per-action `require_step_up` flag).
5. CLI tool adapter with shell injection prevention: command allowlists, max-args enforcement, and denied-arg-token detection (`;`, `&&`, `||`, `|`, `$(`, `` ` ``, `>`, `<`).

### Decision outputs

- `TOOL_ALLOW`
- `TOOL_SCHEMA_INVALID`
- `TOOL_CAPABILITY_DENIED`
- `TOOL_ADAPTER_UNSUPPORTED`
- `TOOL_ACTION_DENIED`
- `TOOL_CLI_COMMAND_DENIED` (CLI adapter: command not in allowlist)
- `TOOL_CLI_ARGS_DENIED` (CLI adapter: args exceed max or contain denied tokens)
- `TOOL_STEP_UP_REQUIRED`

---

## 3.5 Loop Governor v2

### Purpose

External immutable limits for autonomous loops.

### Status: IMPLEMENTED

The loop governor is fully implemented as `loopPlanePolicyEngine` (`POC/internal/gateway/phase3_loop_plane.go`) with an admin API for observability and operator halt (`POC/internal/gateway/admin_phase3.go`).

### Enforced limits

1. max steps
2. max tool calls
3. max model calls
4. max wall time (ms)
5. max egress bytes
6. max model cost (USD)
7. max provider failovers
8. max risk score

### 8-state governance machine

`CREATED` -> `RUNNING` -> `COMPLETED` (terminal)
`RUNNING` -> `WAITING_APPROVAL` -> `RUNNING` (approval granted)
`RUNNING` -> `HALTED_POLICY` (terminal, risk score exceeded)
`RUNNING` -> `HALTED_BUDGET` (terminal, any budget limit exceeded)
`RUNNING` -> `HALTED_PROVIDER_UNAVAILABLE` (terminal)
Any non-terminal -> `HALTED_OPERATOR` (terminal, via admin API or event)

### Technical design

1. durable per-run counters (`loopRunRecord` with usage snapshots)
2. deterministic halting decisions with immutable limit tampering detection (`LOOP_LIMITS_IMMUTABLE_VIOLATION`)
3. reason-code complete responses (15 distinct reason codes)
4. audit correlation for every loop boundary check (decision_id, trace_id)
5. admin API: `GET /admin/loop/runs` (list), `GET /admin/loop/runs/<id>` (detail), `POST /admin/loop/runs/<id>/halt` (operator halt)
6. all admin operations emit audit events via `logLoopAdminEvent`

---

## 3.5.1 RLM Governance Engine

### Purpose

Govern multi-agent lineage tracking, subcall budgets, and UASGS bypass prevention for RLM-style execution patterns.

### Status: IMPLEMENTED

The RLM governance engine is fully implemented as `rlmGovernanceEngine` (`POC/internal/gateway/phase3_rlm.go`).

### Controls

1. Per-lineage state tracking with cumulative resource accounting (`rlmLineageState`).
2. Depth limits: maximum nesting depth for recursive agent calls.
3. Subcall budgets: maximum number of subcalls per lineage.
4. Budget units: maximum cost units per lineage with per-call cost accounting.
5. UASGS bypass prevention: subcalls without `uasgs_mediated=true` are denied with `RLM_BYPASS_DENIED`.
6. Default limits: max_depth=6, max_subcalls=64, max_budget_units=128 (configurable per-request).

### Decision outputs

- `RLM_ALLOW`
- `RLM_SCHEMA_INVALID`
- `RLM_BYPASS_DENIED` (subcall without UASGS mediation)
- `RLM_HALT_MAX_DEPTH` (HTTP 429)
- `RLM_HALT_MAX_SUBCALLS` (HTTP 429)
- `RLM_HALT_MAX_SUBCALL_BUDGET` (HTTP 429)

### Integration

RLM governance is evaluated for every model plane request when `execution_mode=rlm`. The engine runs before model plane policy evaluation; RLM denial short-circuits the request. RLM metadata (lineage_id, depth, budget remaining) is included in all model plane responses when active.

---

## 3.5.2 Ingress Connector Envelope Engine

### Purpose

Canonical connector envelope validation with structured replay detection, source principal authentication, and SHA256 payload content-addressing.

### Status: IMPLEMENTED

The ingress connector envelope engine is fully implemented as `ingressPlanePolicyEngine` (`POC/internal/gateway/phase3_ingress_plane.go`).

### Controls

1. Canonical envelope parsing: connector_type (webhook/queue), source_id, source_principal, event_id, nonce, event_timestamp, payload.
2. Source principal authentication: source_principal must match ActorSPIFFEID.
3. Freshness validation: 10-minute past/future window.
4. Replay detection: composite nonce key (tenant|connector_type|source_id|event_id|nonce) with 30-minute TTL and automatic eviction.
5. SHA256 payload content-addressing: deterministic `ingress://payload/<hex>` reference with raw payload stripped from response.
6. Step-up support: `requires_step_up=true` yields DecisionStepUp.

### Decision outputs

- `INGRESS_ALLOW` (with payload_ref and payload_size_bytes)
- `INGRESS_SCHEMA_INVALID`
- `INGRESS_REPLAY_DETECTED` (HTTP 409)
- `INGRESS_FRESHNESS_STALE` (DecisionQuarantine, HTTP 202)
- `INGRESS_SOURCE_UNAUTHENTICATED` (HTTP 401)
- `INGRESS_STEP_UP_REQUIRED` (HTTP 202)

---

## 3.5.3 Go SDK SPIKE Token Builder

### Status: IMPLEMENTED

The Go SDK provides `BuildSPIKETokenRef` and `BuildSPIKETokenRefWithScope` functions (`POC/sdk/go/mcpgateway/spike_token.go`) that produce Bearer SPIKE token reference strings compatible with the Python SDK format: `Bearer $SPIKE{ref:<ref>,exp:<exp>}` with optional scope qualifier.

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
4. **Indexed evidence integration contract (optional profile)**
   - normalized audit index schema for cross-system queries
   - secure transport and auth requirements (secrets, TLS/mTLS, identity)
   - deterministic query recipes that map control IDs to indexed evidence

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

1. Third-party framework secure integration
2. External context ingestion hardening
3. Sensitive-domain adaptation guidance (K8s baseline + non-K8s mapping)

---

## 8. Definition of Done for Architecture Upgrade

The architecture is considered upgraded when:

1. All solution components in Section 3 are specified in normative terms.
2. Canonical contracts and reason-code catalog are frozen and versioned.
3. Kubernetes-first implementation path is explicit.
4. Compose portability boundaries are explicit for each component.
5. Technical evidence model supports machine-readable auditor consumption.
