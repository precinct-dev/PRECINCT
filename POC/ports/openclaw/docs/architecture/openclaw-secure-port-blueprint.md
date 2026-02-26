# OpenClaw Secure-Port Blueprint and Go/No-Go Gate

**As Of:** 2026-02-16
**Story:** RFA-l6h6.6.9
**Execution Story Status:** RFA-l6h6.6.10 accepted/closed (2026-02-16)
**Post-Gap Reassessment:** RFA-l6h6.6.17.1 accepted/closed (GO beyond framework-closure gate)

## 1. Purpose

Define the secure implementation blueprint for a full OpenClaw port on top of the hardened gateway architecture, with explicit go/no-go criteria before any production-intent implementation starts.

This blueprint is intentionally fail-closed: OpenClaw workloads must run through existing gateway control planes with no direct model/tool bypass path.

## 2. Security Posture Goals

Compared to baseline OpenClaw-style direct integrations, this port must deliver:

| Area | Baseline Risk | Required Improvement |
|------|----------------|----------------------|
| Tool execution path | Direct tool invocation can bypass policy | All tool execution mediated by gateway `/v1/tool/execute` policy path |
| Model egress | Direct provider access possible | Model egress only via gateway model-plane controls and mediation gate |
| Identity | Weak/implicit caller identity | SPIFFE-backed authenticated identity and explicit admin/tool grants |
| Secrets | Raw credential handling risk | Tokenized secret substitution with SPIKE/Nexus patterns |
| High-risk actions | Weak approval semantics | Short-lived, scoped approval capability tokens with strict signing policy |
| Runtime drift | Security controls optional/misaligned | Strict startup profiles and explicit conformance gates |
| Forensics | Limited decision traceability | Hash-chained audit, decision correlation IDs, and replayable evidence |

## 3. Threat Model and Attack Surface

### 3.1 In Scope Threats

1. Direct tool/model bypass attempts from OpenClaw runtime or plugins.
2. Unauthorized control-plane/admin actions.
3. Tool poisoning and policy-registry tampering.
4. Prompt/data exfiltration via multi-step workflows.
5. Replay/freshness abuse on ingress and approval paths.
6. Supply-chain drift (unsigned images/artifacts, stale dependencies).

### 3.2 Non-Goals (for this blueprint)

1. Kernel/node-level hardening outside current platform scope.
2. New cryptographic primitives outside existing approved stack.
3. Replacing SPIFFE/SPIRE, OPA, or audit-chain architecture.

## 4. Integration Boundaries (Module/Test Mapping)

| Boundary | Existing Module(s) | OpenClaw Port Requirement | Evidence Target |
|----------|--------------------|---------------------------|-----------------|
| Tool-plane mediation | `internal/gateway/tool_*`, OPA policy path | Route every OpenClaw tool call via gateway mediation adapters only | Integration + E2E deny bypass tests |
| Model-plane mediation | `internal/gateway/model_*`, enforcement profile controls | Force model requests through gateway model policy gate | Integration tests for deny direct egress |
| Identity/authn/authz | `middleware/spiffe_auth`, admin authz controls | Bind OpenClaw runtime/service identity to SPIFFE and grants | 401/403/allow integration matrix |
| Approval + break-glass | `middleware/approval_capability`, break-glass manager | High-risk actions require scoped approval or bounded break-glass | Capability lifecycle tests + break-glass TTL tests |
| DLP and deep scan | `middleware/dlp*`, `middleware/deep_scan*` | Preserve fail-closed behavior for credentials and gated scan semantics | E2E security-denial scenarios |
| Audit and provenance | `middleware/auditor`, hash chain fields | Correlate OpenClaw actions to decision/audit chain evidence | Evidence bundle checks + chain integrity tests |
| Secrets path | SPIKE/Nexus redeemer + token substitution | No raw secrets in OpenClaw call path; token substitution only | E2E token redemption + deny raw secret injection |
| Network and egress | NetworkPolicies + destination allowlists | Deny direct outbound bypass from OpenClaw workloads | Adversarial egress tests |

## 5. Required Security Invariants (Fail Build If Violated)

1. No direct model provider call path from OpenClaw runtime without gateway mediation.
2. No direct tool execution path bypassing gateway tool-plane checks.
3. No admin/control endpoint callable without authn + authz.
4. No raw secret material in OpenClaw request payloads where token substitution is required.
5. No unsigned/unverified artifact admitted in strict deployment paths.

## 6. Approval and Break-Glass Operating Model

### 6.1 Default Mode

- High-risk operations require approval capability tokens.
- Tokens are scoped, signed, time-bounded, and single-use/consumed on use.
- Missing/weak signing key is startup-fatal in strict profiles.

### 6.2 Break-Glass Mode

- Break-glass remains bounded and auditable.
- Must include:
  - explicit reason code,
  - bounded TTL,
  - issuer identity,
  - immutable audit event sequence.
- Break-glass cannot disable baseline identity or audit requirements.

## 7. Go/No-Go Gate for RFA-l6h6.6.10

Execution is **NO-GO** unless all required gates below are true:

| Gate | Source Story | Required State |
|------|--------------|----------------|
| Admin/authz hardening complete | RFA-l6h6.6.1 | Accepted |
| EKS/gateway transport wiring aligned | RFA-l6h6.6.2 | Accepted |
| Admission scope alignment complete | RFA-l6h6.6.3 | Accepted |
| Network policy least privilege complete | RFA-l6h6.6.4 | Accepted |
| Approval key hardening complete | RFA-l6h6.6.5 | Accepted |
| mTLS peer identity pinning complete | RFA-l6h6.6.6 | Accepted |
| CI/security automation aligned | RFA-l6h6.6.7 | Accepted |
| Documentation reconciliation complete | RFA-l6h6.6.8 | Accepted |

Go decision criteria:

- **GO**: every gate above accepted, blueprint checklist complete, and decomposition below adopted.
- **NO-GO**: any gate open/rejected, or any invariant in Section 5 lacks explicit test coverage target.

## 8. Blueprint Completeness Checklist (Planning Test)

- [x] Threat model and attack surfaces defined.
- [x] Control boundaries mapped to concrete modules and test suites.
- [x] Explicit denial of direct model/tool bypass is specified.
- [x] Approval and break-glass models are specified.
- [x] Go/no-go criteria reference accepted closure stories.
- [x] Backlog decomposition is provided with test/evidence targets.

## 9. Backlog Decomposition for RFA-l6h6.6.10

The implementation backlog is decomposed into self-contained work packages that can be executed under `RFA-l6h6.6.10`:

| Package | Objective | Primary Deliverables | Test/Evidence Target |
|---------|-----------|----------------------|----------------------|
| WP-1 OpenClaw ingress adapter | Bind OpenClaw runtime entrypoints to gateway contracts | Adapter layer, request normalization, identity propagation | Integration contract tests |
| WP-2 Tool-plane enforcement | Ensure all OpenClaw tool calls traverse policy/tool registry controls | Tool adapter wiring, bypass denial guards | Adversarial bypass E2E |
| WP-3 Model-plane enforcement | Route model calls through model mediation/residency/policy controls | Model adapter wiring, deny direct provider path | Direct egress deny tests |
| WP-4 Approval + break-glass workflows | Integrate high-risk approval lifecycle and bounded emergency controls | Approval token plumbing, break-glass bounded flow | Lifecycle + abuse-case tests |
| WP-5 Secret handling hardening | Enforce token substitution and SPIKE/Nexus redemption | Secret path integration, raw-secret deny policies | Token redemption E2E + DLP deny |
| WP-6 Audit/provenance evidence | Ensure complete OpenClaw decision trace and correlation IDs | Audit field mapping and chain verification | Hash-chain and correlation checks |
| WP-7 Operational runbooks | Incident response + rollback procedures for OpenClaw integration | Playbooks, rollback commands, failure triage guides | Runbook walkthrough evidence |
| WP-8 Comparative posture report | Quantify security posture delta vs baseline OpenClaw runtime | Structured comparison report + residual risk register | Signed evidence artifact |

## 10. Requirement Traceability Matrix

| Requirement | Implementation Story | Evidence Target |
|-------------|----------------------|-----------------|
| No tool/model bypass path | RFA-l6h6.6.10 (WP-2, WP-3) | Adversarial deny tests + route-level proofs |
| Security controls active in real integrations | RFA-l6h6.6.10 (WP-1 through WP-6) | Integration + E2E pass matrix |
| Comparative posture report | RFA-l6h6.6.10 (WP-8) | Delta report with residual risk section |
| Incident + rollback readiness | RFA-l6h6.6.10 (WP-7) | Runbook validation artifacts |

## 11. Recommendation

Current recommendation: implementation and framework-closure reassessment gates are satisfied. Maintain this blueprint as the security baseline and rerun promotion evidence when upstream `~/workspace/openclaw` changes materially.
