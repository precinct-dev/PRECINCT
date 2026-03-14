# Agentic Zero Trust FAQ

This is a living FAQ for security and architecture reviews of the agentic gateway design.
It captures recurring stakeholder questions and answer patterns grounded in the current implementation.

## Scope

- Focus: zero trust posture for agent identity, policy, context control, egress, provenance, and response operations.
- Source of truth: implementation and architecture docs in this repository.
- Status model for each answer:
  - `Implemented` means it exists in runtime code paths today.
  - `Partially Implemented` means pieces exist but material hardening or protocol coverage is still needed.
  - `Roadmap` means architectural intent exists but no first-class runtime surface is wired yet.

## Frequently Asked Questions

### 1) Why is this agent identity pattern appropriate for zero trust?

**Short answer:** Workloads use SPIFFE/SPIRE identity and mTLS in production, so identity is cryptographic, short-lived, and attributable per workload instead of static credentials.

**Status:** Implemented

**What to emphasize**

- Identity is extracted from verified mTLS cert URI SANs in production mode.
- Policy and audit layers consume the same identity context.
- Peer authorization can pin expected SPIFFE IDs.
- Development mode header identity is explicitly a non-production convenience.

### 2) How do we tightly control what goes into and out of model/tool context?

**Short answer:** The gateway enforces deterministic, ordered middleware plus fail-closed context invariants, with DLP and prompt-safety controls before high-risk actions.

**Status:** Implemented

**What to emphasize**

- Input path includes size guard, identity, OPA authz, DLP, session context, step-up gating, deep scan.
- Output path includes response firewall and handle-based data indirection for sensitive responses.
- Context invariants enforce principles like minimum necessary and no-scan-no-send.
- Session context tracks risky cross-tool flows for exfiltration detection.

### 3) How are external calls controlled, and how do we prevent bypass?

**Short answer:** Calls are mediated through the gateway, with tool registry verification, policy checks, destination controls, and network-level segmentation.

**Status:** Implemented (with hardening caveats)

**What to emphasize**

- `tools/call` cannot bypass registry verification logic.
- Rug-pull protection compares approved baseline hashes against observed upstream metadata.
- Step-up and allowlisted destinations gate risky egress.
- Kubernetes NetworkPolicies provide default-deny and gateway-only ingress patterns.
- Compose mode has documented security boundaries and compensating controls.

### 4) What is our proof and provenance model, including subpoena-response readiness?

**Short answer:** Every decision is correlated with stable IDs and identity fields, linked to policy/registry digests, and chain-verifiable via hash-linked audit events.

**Status:** Implemented (stronger in K8s immutable sink mode)

**What to emphasize**

- Audit records include `decision_id`, `trace_id`, `session_id`, and `spiffe_id`.
- Each record carries `prev_hash`, `bundle_digest`, and `registry_digest`.
- Hash-chain verification tooling exists for tamper-evidence checks.
- CLI tooling supports searchable, explainable decision reconstruction.
- K8s path includes object-lock-oriented immutable sink validation; Compose has explicit limitations.

### 5) What is our PII management and prompt safety story?

**Short answer:** The gateway enforces DLP and prompt-safety controls before execution, with deny/quarantine/tokenize/redact pathways depending on policy profile.

**Status:** Implemented

**What to emphasize**

- Credential leakage is blocked as a security invariant.
- PII and injection patterns are detected and policy-gated.
- Regulated profiles enforce stricter prompt-safety handling.
- Response firewall and handle dereference controls reduce raw sensitive payload exposure to agents.

### 6) How can we trust the overall design?

**Short answer:** Trust comes from layered controls plus verifiability, not one control point.

**Status:** Implemented with explicit profile-dependent assurance levels

**What to emphasize**

- Identity + policy + DLP + step-up + deep scan + response firewall stack.
- Runtime profiles provide strict startup conformance in production profiles.
- Audit and trace correlation support investigation and accountability.
- Published boundaries make dev/compose limitations explicit instead of implicit.

### 7) Privilege model: just-in-time vs just-in-case?

**Short answer:** Baseline least privilege is static; high-risk privileges are expected to be just-in-time via bounded approval capabilities.

**Status:** Implemented

**What to emphasize**

- Static grants define default least-privilege bounds.
- High-risk operations require scoped, TTL-bounded, single-consume approvals.
- Approval tokens are bound to action/resource/actor/session.

### 8) Should the agent see OPA controls ahead of time to avoid bad behavior?

**Short answer:** Runtime enforcement exists now; proactive policy projection to the agent should be added for better planning behavior.

**Status:** Partially Implemented

**What to emphasize**

- Today: strong runtime enforcement and structured denial reasons.
- Gap: no first-class signed “effective capabilities” manifest endpoint for preflight planning.
- Recommendation: expose policy-derived, digest-bound capability summaries for agent planning while preserving enforcement authority at the gateway.

### 9) WebMCP dynamic page tools seem to break the static tool registry model. What is our position?

**Short answer:** The current registry model is robust for stable tools; dynamic web-exposed tools require an ephemeral trust layer on top of baseline registry controls.

**Status:** Partially Implemented

**What to emphasize**

- Existing controls already defend against tool metadata rug-pull and unauthorized invocation.
- Dynamic tool ecosystems should add:
  - origin/issuer trust constraints
  - page/content hash binding
  - schema hash + TTL-based ephemeral registrations
  - full audit provenance for discovered capabilities

### 10) A2A protocol seems missing from gateway implementation. Is that true?

**Short answer:** A2A is covered architecturally, but not yet as a first-class dedicated runtime gateway surface in this POC.

**Status:** Roadmap

**What to emphasize**

- Architecture guidance exists to treat A2A as another governed interface.
- Recommendation is to terminate A2A through gateway controls (identity, policy, scanning, audit), similar to MCP/tool traffic.

### 11) How do we do live inspection of a running system at any point in time?

**Short answer:** We have live status and admin introspection endpoints now, plus trace/audit tooling; a signed point-in-time control-state snapshot would further strengthen forensic posture.

**Status:** Implemented (with enhancement opportunity)

**What to emphasize**

- Existing endpoints expose health, enforcement profile status/export, loop metadata, break-glass status, and policy reload state.
- CLI commands support operational status and decision-level audit explainability.
- Enhancement: add a single immutable “state snapshot” artifact endpoint for incident response.

### 12) What is our immutable logs story?

**Short answer:** K8s-first immutable evidence path is defined and machine-validated; Compose mode uses compensating controls and is explicitly not equivalent.

**Status:** Implemented (K8s), Compensating Controls (Compose)

**What to emphasize**

- Hash-chained audit events with provenance digests.
- K8s immutable sink validation and artifactized proof flow.
- Clear declaration of Compose limits and compensating measures.

### 13) Do we have HITL and kill switch controls?

**Short answer:** HITL exists via approval and step-up workflows; kill switch exists for MCP-UI; a global cross-plane emergency stop should be added.

**Status:** Partially Implemented

**What to emphasize**

- HITL: approval request/grant/deny/consume with bounded tokens.
- Emergency override: bounded dual-approval break-glass lifecycle with elevated audit markers.
- Current kill switch is explicit for UI capability path.
- Gap: no single global “deny all high-risk actions” switch across tool/model planes.

### 14) Can the gateway keep a narrow-purpose agent on mission, even when the user asks for something harmless but off-topic?

**Short answer:** Yes. The model plane now supports mission-bound mediation so
builders can declare a narrow-purpose agent mission and have the gateway deny or
safely rewrite out-of-scope prompts before any upstream model call is made.

**Status:** Implemented

**What to emphasize**

- This addresses a different failure mode than classic prompt injection.
- Prompt-injection controls look for hostile instructions; mission-bound
  mediation enforces business/task scope even for harmless prompts.
- The contract is generic: agent purpose, allowed intents/topics, blocked
  topics, enforcement mode, and out-of-scope action.
- The gateway remains authoritative; SDKs and packs only supply declarative
  inputs.
- Safe fallback mode can return a synthetic assistant response so customer
  support agents redirect politely instead of answering off-mission questions.
- Demo coverage exists for the concrete case of a restaurant support agent being
  asked for Python linked-list help.

## Operational Notes For Reviewers

- Always state environment when answering: `dev/compose` versus `prod/k8s`.
- Avoid overselling controls that are profile-dependent.
- Include residual risk explicitly when a control is partial or roadmap.

## Intake Template (Add New FAQ Entries)

Use this block for each new stakeholder question:

```markdown
### N) <Question>

**Short answer:** <1-3 sentences>

**Status:** <Implemented | Partially Implemented | Roadmap>

**What to emphasize**

- <control, evidence, and limits>
- <residual risk and mitigation path>
```
