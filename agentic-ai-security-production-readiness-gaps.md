# Agentic AI Security Production Readiness Gap Analysis

**Status:** Draft for architecture review  
**Date:** 2026-02-13  
**Reviewed baseline:** `agentic-ai-security-reference-architecture.md` (v2.3)  
**Assessed implementation:** `POC/` (gateway, policies, infra, compliance tooling)

---

## 1. Objective

Define all material gaps between:

1. The production claims and control obligations in the reference architecture, and
2. The current POC implementation,

so we can converge on a production-ready architecture for:

- sensitive domain assistants (e.g., regulated healthcare or biotech on Fargate or EKS),
- third-party framework integrations requiring mediated model egress,
- external context ingestion pipelines with provenance and quarantine,
- compliance-bound enterprise agents (ISO 27001, ITSM, SOC 2).

This document includes Phase 3 incompleteness explicitly and proposes the required architectural additions/changes.

Scope posture for this architecture/reference implementation:

1. **Kubernetes-first technical reference** (portable model, validated in local Kubernetes).
2. **No proprietary environment packs as a core deliverable** (e.g., no mandatory ECS/Fargate/GCP turnkey pack).
3. **Strong adaptation documentation** so teams can map invariants safely into proprietary/non-K8s environments.
4. **Compliance support is technical**: controls, evidence generation, machine-readable outputs, and auditor-readable documentation.
5. **People/process programs** (tabletops, org governance operations) are acknowledged but out of scope for implementation deliverables.

---

## 2. Executive Verdict

The architecture is **strong in core MCP tool-plane security**, but it is **not yet production-ready for all stated use cases**.

Top reasons:

1. Phase 3 control planes are only partially implemented (several are scaffolding/minimal logic).
2. Production go/no-go controls are not fully proven end-to-end (notably conformance gates, connector governance, RuleOps lifecycle, break-glass, legal-hold-grade audit workflows).
3. Compliance automation is meaningful but narrow; it does not yet span all required control areas for SOC 2 Type II / ISO 27001 / CCPA-CPRA / GDPR, and does not yet include PCI-DSS.
4. Non-K8s/proprietary environment adaptation guidance is not yet strong enough to guarantee safe portability without design drift.

---

## 3. Method

Review basis:

- Full reference architecture sections 1-13 (`agentic-ai-security-reference-architecture.md`).
- Production requirements and go/no-go criteria (`10.13.6`, `10.13.7`, `10.14`, `10.15`, `10.19`).
- Phase 3 roadmap commitments (`12`).
- Current POC state and code (`POC/docs/current-state-and-roadmap.md`, `POC/internal/gateway/phase3_*`, middleware, infra docs).

Assessment style:

- `Implemented`: present and materially aligned.
- `Partial`: present but materially incomplete for production.
- `Missing`: required by architecture but absent.

---

## 4. Detailed Gap Register

## G-01: Ingress Connector Conformance Is Missing

- **Architecture requirement:** `7.12`, `10.14.2`, `10.19` require connector conformance and signed manifests before enablement.
- **Current state:** No connector conformance framework, no signed manifest verification, no connector registry lifecycle.
- **Evidence:** Reference requires it; POC has no connector conformance tests/endpoints.
- **Risk:** Non-conformant ingress paths can bypass expected envelope guarantees and provenance assumptions.
- **Status:** `Missing`
- **Required change:** Add Connector Conformance Authority (manifest schema, signature verification, conformance tests, runtime deny on non-conformant connectors).

## G-02: DLP RuleOps Control Plane Is Scaffolding

- **Architecture requirement:** `7.5.2`, `9.8`, `10.14.2` (RBAC/SOD, dual approval, signing, canary, rollback, audit lifecycle).
- **Current state:** Read-only introspection only; no CRUD lifecycle.
- **Evidence:** `POC/internal/gateway/phase3_dlp_ruleops.go`, `POC/internal/gateway/admin_phase3.go`.
- **Risk:** DLP policy drift/tampering cannot be governed at production grade.
- **Status:** `Partial`
- **Required change:** Implement `/v1/dlp/rulesets/*` state machine with approval workflows, signature checks, canary activation, rollback, immutable audit events.

## G-03: Context Admission Invariants Are Incomplete

- **Architecture requirement:** `7.11` mandates `no-scan-no-send`, `no-provenance-no-persist`, `no-verification-no-load`, `minimum-necessary`.
- **Current state:** Context endpoint checks only a subset (`scan_passed`, `prompt_check_passed`, injection flag).
- **Evidence:** `POC/internal/gateway/phase3_runtime_helpers.go` (`handleContextAdmit`).
- **Risk:** Unverified or non-minimized external context can still be persisted/loaded.
- **Status:** `Partial`
- **Required change:** Enforce all four invariants with explicit provenance object requirements, verification tokens, and size/token minimization policies.

## G-04: Tool Plane Endpoint Does Not Enforce Capability Governance

- **Architecture requirement:** Phase 3 tool plane with capability and adapter constraints.
- **Current state:** `/v1/tool/execute` returns allow with minimal metadata.
- **Evidence:** `POC/internal/gateway/phase3_runtime_helpers.go` (`handleToolExecute`).
- **Risk:** Phase 3 tool-plane contract exists without real enforcement boundary.
- **Status:** `Partial`
- **Required change:** Enforce capability registry v2 checks, adapter protocol policy, action-level allowlists, and step-up requirements for irreversible operations.

## G-05: Loop Governance Is Minimal

- **Architecture requirement:** Loop plane limits across steps, tool calls, model calls, wall time, egress bytes, cost, failovers, risk.
- **Current state:** Only `max_steps` is enforced in endpoint logic.
- **Evidence:** `POC/internal/gateway/phase3_runtime_helpers.go` (`handleLoopCheck`).
- **Risk:** No robust external loop governor for high-autonomy agent flows.
- **Status:** `Partial`
- **Required change:** Enforce full immutable limit set with durable counters and reason-code-complete denial paths.

## G-06: Human Approval Path Is Still a Stub

- **Architecture requirement:** High-risk actions require approval/capability issuance (`7.7`, `10.14.1`, `10.7.4`).
- **Current state:** approval gate returns deny stub (`human approval required`).
- **Evidence:** `POC/internal/gateway/middleware/step_up_gating.go`.
- **Risk:** No production-ready approval capability for critical actions.
- **Status:** `Partial`
- **Required change:** Add approval service with identity-bound, time-boxed approval tokens and full audit lineage.

## G-07: Break-Glass Governance Is Not Implemented

- **Architecture requirement:** `10.13.6` requires bounded, authenticated, audited break-glass.
- **Current state:** No explicit break-glass contract/service/policy path.
- **Risk:** Emergency operations lack controlled override mechanics.
- **Status:** `Missing`
- **Required change:** Add break-glass control plane (dual auth, strict TTL, scope-bound override, mandatory audit marker).

## G-08: Enforcement Profiles Are Not Materialized

- **Architecture requirement:** `dev`, `prod_standard`, `prod_regulated_hipaa` resolved defaults (`10.13.7`).
- **Current state:** Not implemented as profile bundles/gates in POC runtime.
- **Risk:** Inconsistent environment behavior and unverifiable production posture.
- **Status:** `Missing`
- **Required change:** Implement profile bundles with immutable defaults + startup conformance checks.

## G-09: Conformance Test Suites Are Missing

- **Architecture requirement:** `10.19` calls for policy, connector, RuleOps, and HIPAA profile conformance suites.
- **Current state:** No dedicated conformance suite layer.
- **Risk:** Production claims cannot be objectively gated.
- **Status:** `Missing`
- **Required change:** Add contract test harness + certification gates for each deployment pack/profile.

## G-10: Audit Durability and Legal-Hold Workflow Not End-to-End Proven

- **Architecture requirement:** immutable audit store + retention/legal hold (`10.9`, `10.13.6`).
- **Current state:** Hash-chained local JSONL is implemented; EKS S3 Object Lock artifacts exist, but not proven in a live production deployment.
- **Evidence:** `POC/internal/gateway/middleware/audit.go`, `POC/infra/eks/observability/audit/*`, `POC/docs/current-state-and-roadmap.md` (EKS not deployed).
- **Risk:** Subpoena/eDiscovery readiness remains design-level for cloud profiles.
- **Status:** `Partial`
- **Required change:** Deliver and validate live immutable sink path (write, retention, legal hold, restore/query runbooks).

## G-11: Model Egress Trust Policy Is Incomplete for High Assurance

- **Architecture requirement:** endpoint trust policy, DNS integrity, no-bypass gates, signed allowlist updates (`10.17`).
- **Current state:** allowlist + TLS minimum version + provider policy exist; no explicit DNS integrity controls, no signed allowlist lifecycle for model egress policy.
- **Evidence:** `POC/internal/gateway/phase3_model_egress.go`, `POC/internal/gateway/phase3_model_plane.go`.
- **Risk:** Residual provider-routing drift and trust-policy gaps.
- **Status:** `Partial`
- **Required change:** Add signed provider catalog, DNS integrity policy module, certificate identity policy, and drift detection with fail-closed options by profile.

## G-12: Model Artifact Integrity Controls Not Implemented as Runtime Gates

- **Architecture requirement:** model weight digest/signature verification with fail-closed behavior (`10.5`).
- **Current state:** architecture guidance exists; runtime guard-model artifact verification gates are not implemented.
- **Risk:** compromised guard model artifacts can evade detection controls.
- **Status:** `Missing`
- **Required change:** Add model artifact verifier at startup/admission + provenance attestation for guard artifacts.

## G-13: Endpoint/Reason-Code Contract Drift Between Reference and POC

- **Architecture reference examples:** e.g., `/v1/ingress/submit`, HIPAA reason-code set.
- **Current state:** POC uses `/v1/ingress/admit`; different prompt-safety reason codes.
- **Evidence:** `agentic-ai-security-reference-architecture.md` vs `POC/internal/gateway/phase3_runtime_helpers.go` and `POC/internal/gateway/phase3_contracts.go`.
- **Risk:** integration ambiguity and brittle client contracts.
- **Status:** `Partial`
- **Required change:** freeze canonical contract set and publish versioned API + reason-code catalog.

## G-14: Non-K8s Adaptation Guidance Is Not Yet Hardened

- **Architecture requirement:** profile C (cloud container services) defines required controls (`10.13.3`) and portability intent (`10.19`).
- **Current state:** guidance exists, but adaptation mapping is not yet strong enough as a practical engineering playbook.
- **Risk:** teams adapting to ECS/Fargate/Cloud Run/ACA may accidentally weaken invariants.
- **Status:** `Partial`
- **Required change:** publish a hardened adaptation guide (no proprietary pack) with invariant mapping, reference policy templates, and verification checklist for non-K8s environments.

## G-15: EKS Production Readiness Not Runtime-Validated

- **Architecture requirement:** profile D production assurance.
- **Current state:** EKS manifests validated offline; not deployed and exercised in live cluster.
- **Evidence:** `POC/docs/current-state-and-roadmap.md`.
- **Risk:** policy/network/admission behaviors remain unproven in real cloud runtime.
- **Status:** `Partial`
- **Required change:** run production-like EKS validation campaign with attack simulations, failover drills, and evidence snapshots.

## G-16: Compliance Technical Coverage and Evidence Model Are Too Narrow

- **Required target:** complete **technical** control mapping and evidence output for SOC 2 Type II, ISO 27001, CCPA/CPRA, GDPR.
- **Current state:** compliance automation maps 33 controls, mostly gateway-security-centric.
- **Evidence:** `POC/tools/compliance/control_taxonomy.yaml`, `POC/tools/compliance/generate.py`.
- **Risk:** insufficient technical coverage and incomplete machine-readable evidence packaging for auditor consumption.
- **Status:** `Partial`
- **Required change:** expand technical control library and evidence model (machine-readable first), including traceability from control to generated evidence artifacts.

## G-17: PCI-DSS Profile Is Absent

- **Target requirement:** optional but in-scope with clear delivery path.
- **Current state:** no PCI-DSS mapping/profile/pack in architecture implementation.
- **Status:** `Missing`
- **Required change:** create PCI-DSS control pack (segmentation, PAN handling, key management, logging/monitoring, vulnerability mgmt, annual controls).

## G-18: HIPAA Profile Is Partial

- **Architecture target:** regulated profile with deny/tokenize behavior and profile conformance.
- **Current state:** prompt-safety controls exist, but full HIPAA profile contract + operational safeguards are incomplete.
- **Status:** `Partial`
- **Required change:** formal HIPAA profile pack: PHI classification, tokenization/re-identification controls, BAAs/vendor boundary controls, retention and disclosure workflows.

---

## 5. Compliance Scope and Technical Gap View

Deliverable boundary for this project:

1. Provide robust technical controls and technical evidence outputs.
2. Provide auditor-readable technical documentation and machine-readable evidence.
3. Do not attempt to replace organization-specific people/process programs.

Technical control/evidence gap view:

| Technical Domain | SOC2 Type II | ISO 27001 | CCPA/CPRA | GDPR | Current State |
|---|---|---|---|---|---|
| Identity/access, authz, least privilege | Covered | Covered | Partial | Partial | Strong technical coverage |
| Cryptography/secrets and key handling | Covered | Covered | Partial | Partial | Strong technical coverage |
| Tool/model/context/ingress policy enforcement | Partial | Partial | Partial | Partial | Phase 3 incomplete |
| Audit integrity, correlation, machine-readable logs | Covered | Covered | Partial | Partial | Strong core; immutable sink proof incomplete |
| Artifact integrity and supply-chain controls | Partial | Partial | Partial | Partial | Good image controls; model/policy provenance incomplete |
| Data deletion/retention technical hooks | Partial | Partial | Partial | Partial | GDPR delete present; full evidence linkage needs expansion |
| Evidence export completeness (machine-readable) | Partial | Partial | Partial | Partial | Current report scope too narrow for full technical mapping |

Out of scope for implementation deliverables (but acknowledged): org governance workflow design, tabletop exercises, enterprise-wide policy operations outside system technical boundaries.

---

## 6. Architecture Additions Required (vNext)

## A. Phase 3 Completion Layer

1. **Connector Conformance Authority**  
   Signed connector manifests, conformance test execution, runtime registration gate.
2. **RuleOps Service (DLP and policy artifacts)**  
   Full lifecycle with RBAC/SOD/dual approval/signing/canary/rollback.
3. **Approval + Break-Glass Service**  
   Time-boxed capability tokens, emergency overrides, mandatory audit markers.
4. **Full Context Admission Engine**  
   Enforce all invariants, provenance checks, minimum-necessary transformations.
5. **Loop Governor Service**  
   Durable budget counters and complete immutable limit enforcement.

## B. Production Evidence Fabric

1. Immutable audit sink patterns for each profile (EKS, Fargate, VM, on-prem).
2. Legal hold and retention policy automation hooks.
3. Conformance evidence bundles as release artifacts.

## C. Compliance Control Library

1. Extend control taxonomy beyond gateway-only technical controls.
2. Add ownership model (`Control Owner`, `Evidence Source`, `Test Cadence`, `Exception Path`).
3. Add profile-specific packs:
   - `table_stakes` (SOC2/ISO27001/CCPA-CPRA/GDPR),
   - `pci_dss`,
   - `hipaa`.

## D. Platform Adaptation Guides

1. **Kubernetes Reference Hardening Guide** (live-validated baseline and portability assumptions).
2. **Cloud Container Adaptation Guide** (non-K8s mapping for identity/egress/audit/artifact invariants; no proprietary turnkey pack).
3. **On-Prem Adaptation Guide** (Keycloak/HSM/legal-hold integration patterns).

---

## 7. Use-Case Readiness Delta

| Use Case | Current Readiness | Critical Missing Pieces |
|---|---|---|
| Sensitive domain assistant (Fargate/EKS) | Partial | non-K8s adaptation hardening guide, connector conformance, RuleOps lifecycle, immutable audit proven in target runtime |
| Third-party framework integration | Low | Implementation not started beyond architecture sketch |
| External context ingestion pipeline | Partial | Context fetcher/ingestion hardening, provenance and verification invariants, loop governance completeness |
| ISO 27001 + ITSM compliance agents | Partial | technical control library expansion, PCI pack, stronger technical evidence and break-glass capabilities |

---

## 8. Proposed Delivery Sequence

## Wave 1 (Blockers)

1. Phase 3 contract freeze (endpoints + reason codes + profile semantics).
2. Connector conformance + RuleOps MVP with signed artifacts.
3. Approval service + break-glass controls.
4. Full context invariants implementation.

## Wave 2 (Production Baselines and Adaptation)

1. EKS live validation campaign and conformance evidence.
2. Publish and validate cloud-container adaptation guide (no proprietary pack commitment).
3. Immutable audit + legal hold runbooks validated.

## Wave 3 (Compliance Expansion)

1. Expanded SOC2/ISO27001/CCPA-CPRA/GDPR technical control library.
2. PCI-DSS and HIPAA profile packs with test suites.
3. Unified compliance evidence pipelines and control ownership model.

## Wave 4 (Use-Case Closure)

1. Third-party framework integration implementation and soak validation.
2. External context ingestion hardening and policy certification.
3. Compliance-bound enterprise agent pilot with regulator-style evidence review.

---

## 9. Exit Criteria for “Production Ready for All Target Use Cases”

All must be true:

1. All Phase 3 gaps (`G-01` to `G-09`) are closed with conformance tests.
2. Kubernetes reference implementation passes production go/no-go checks, and non-K8s adaptation guidance is complete with invariant-based verification checklists.
3. Immutable audit, legal hold, and forensic query workflows are operationally proven.
4. Table-stakes framework **technical** control library is complete with evidence automation and machine-readable outputs.
5. PCI-DSS and HIPAA packs exist with documented implementation and test paths.
6. All target use cases have executed hardening acceptance scenarios.

---

## 10. Immediate Next Step

Use this document as the architectural decision baseline for vNext planning.  
Convert each gap (`G-01`...`G-20`) into backlog epics/stories with explicit conformance evidence requirements.
