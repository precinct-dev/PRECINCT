# OpenClaw Adaptation Guide (Enterprise-Hardened via UASGS)

Status: Draft (architecture-level proposal for a future port/adaptation)

This document describes how to adapt **OpenClaw** (a popular consumer-oriented, multi-channel agentic system) to run inside the **Agentic AI Security Reference Architecture** using the **Unified Agentic Security Gateway System (UASGS)**, with **surgery rather than a complete re-engineering**.

The point of the exercise is not to “fix OpenClaw,” but to show that our architecture can constrain a real-world, channel-heavy agent to an enterprise-defensible posture even when deployed locally (Docker Compose) and later in production (managed Kubernetes / leading cloud providers).

## 1. Scope And Assumptions

### In scope
- Mapping OpenClaw’s core surfaces to UASGS planes:
  - LLM egress (“brain”)
  - Context/Memory
  - Tools/Actions
  - Control loop (non-intrusive governance)
  - Ingress (events, webhooks, chat channels)
- Minimal-change integration points (“where to cut”).
- Controls that remain enforceable even in Docker Compose (local laptop).
- Residual gaps that are inherently operational/governance-driven (documented clearly).

### Out of scope
- Implementing the OpenClaw port in code in this repo (that is a later phase).
- Replacing OpenClaw’s internal UX/TUI/web UI.
- Achieving “perfect” parity with a hardened K8s environment when running purely on a laptop.

### Reference points (factual anchors in OpenClaw source)
The guidance here is grounded in OpenClaw’s current structure and behavior at:
- OpenClaw repo: `/Users/ramirosalas/workspace/openclaw`
- Commit: `5c32989f53310f52dc93c428561424eaa0f15c17`

Examples of relevant OpenClaw entry points:
- Multi-provider model key resolution (env + profiles): `src/agents/model-auth.ts`
- SSRF guard with DNS pinning: `src/infra/net/fetch-guard.ts`, `src/infra/net/ssrf.ts`
- Multi-channel routing and policy glue: `src/channels/dock.ts`, `src/channels/registry.ts`
- Tooling that performs direct network fetches: `src/agents/tools/web-fetch.ts`
- Skill scanner (static-ish scanning of skill source code): `src/security/skill-scanner.ts`

## 2. Threat Model Snapshot (Why OpenClaw Is Risky In Enterprise)

OpenClaw is designed to be powerful and convenient, which implies:
- Many **untrusted ingress** paths (Telegram/WhatsApp/Slack/Discord/Signal/etc) and webhook triggers.
- Many **direct egress** paths (model provider calls, web fetch/search tools, media downloaders, embeddings APIs).
- **Secrets as env/config** is the happy path (e.g., `GROQ_API_KEY`, `ZAI_API_KEY`, `OPENAI_API_KEY` in `src/agents/model-auth.ts`).
- Skills/plugins may include code execution, file access, and network access (OpenClaw mitigates some with scanning, but it’s not an enterprise policy boundary).

In a regulated enterprise, the strongest position is:
1. **No direct-to-Internet egress from the agent runtime.**
2. **No raw secrets in app env/config** (use referential secrets).
3. **Every ingress and every context contribution is treated as hostile until proven otherwise.**
4. **All external actions are governed and audited at one authority boundary (UASGS).**

## 3. Adaptation Strategy: “Enforce From The Outside”

OpenClaw already has internal safety features (SSRF guards, skill scanners, etc.). We keep them as defense-in-depth, but we do not “trust” them as the primary control boundary.

The architecture posture is:
- **OpenClaw becomes an agent runtime that must operate inside a constrained environment.**
- **UASGS becomes the mandatory policy boundary** for:
  - model provider egress
  - tool execution and network I/O
  - ingress admission
  - context/memory admission
  - budget enforcement and reason-coded outcomes
- Network segmentation + identity gates ensure **no-bypass** in production profiles.

This matches our Phase 3 posture: high-assurance controls are centralized, while frameworks keep “illusion of freedom.”

## 4. Mapping OpenClaw To UASGS Planes

### 4.1 Ingress Plane (Events, Webhooks, Multi-Channel Chat)

OpenClaw has a channel system and supports multiple chat “front doors” (see `src/channels/registry.ts`, `src/channels/dock.ts`). From an enterprise perspective, each of these channels is an untrusted ingress source.

**Target architecture mapping**
- Channel traffic MUST be wrapped in the UASGS ingress envelope and submitted to **Ingress Admission** before it can:
  - update session state
  - write memory
  - influence prompts/context
  - trigger tools/actions

**Key adaptation decision (recommended)**
- Do not make UASGS a universal protocol gateway for Telegram/WhatsApp/etc.
- Instead, deploy **Channel Connectors** as “tool-plane adjacent” services (or separate ingress workers) that:
  - speak Telegram/WhatsApp/Slack/etc protocols
  - convert inbound events into the UASGS ingress envelope
  - submit them to UASGS Ingress Admission
  - receive an allow/deny + reason code decision
  - (if allowed) forward the sanitized/admitted message to OpenClaw’s internal agent entrypoint

This keeps UASGS protocol-agnostic while still ensuring consistent, centralized security enforcement.

**Outbound messages**
- OpenClaw responses should not directly call channel APIs from the agent runtime.
- Provide outbound messaging as governed tools (e.g., `send_message(channel=telegram, ...)`) executed via the UASGS Tool Plane against the Channel Connector.

### 4.2 Model Plane (Provider Governance, Residency, Budgets)

OpenClaw resolves provider credentials from profiles and environment variables (see `src/agents/model-auth.ts`), including keys like `ZAI_API_KEY` and `GROQ_API_KEY`.

**Target architecture mapping**
- OpenClaw must not hold raw keys at runtime.
- OpenClaw must not call providers directly.
- OpenClaw model calls are routed through **UASGS Model Plane**, which enforces:
  - allowed provider endpoints (and TLS/DNS integrity policies)
  - data residency policy
  - budget/cost policy (provider quota constraints)
  - prompt safety/DLP policy (including HIPAA “minimum necessary” profile)
  - per-session limits (timeouts, max steps, max tokens)
  - detailed reason-coded denial and audit events

**Minimal change approach**
- Prefer an OpenAI-compatible “base URL” redirection (where OpenClaw supports it) so that existing provider client code can point at UASGS without refactoring call sites.
- If OpenClaw uses multiple API shapes (“openai-completions”, “openai-responses”), UASGS should expose compatible endpoints (or provide a tiny compatibility shim).

**Budgets introduce new failure modes**
- When a budget is exhausted, UASGS returns a reason-coded denial.
- OpenClaw can optionally implement fallback provider logic, but even without code changes, the operator must get clear audit/log evidence explaining:
  - which policy failed (budget, residency, endpoint trust, prompt safety)
  - which provider/model was attempted
  - what fallback (if any) was selected

### 4.3 Tool Plane (Actions, Web Fetch/Search, External Capabilities)

OpenClaw tools like web fetch perform direct network calls and include defense-in-depth wrappers (see `src/agents/tools/web-fetch.ts` calling `fetchWithSsrFGuard`).

**Target architecture mapping**
- Tool execution should be mediated through the UASGS Tool Plane, including:
  - allowlists and schema validation
  - step-up gating
  - response firewall (output filtering / DLP)
  - per-tool budgets and rate limits
  - deterministic audit evidence

**Minimal change approach**
- Disable or restrict OpenClaw “direct network tools” in the agent runtime profile.
- Re-expose those capabilities through UASGS-governed tools:
  - `web_fetch` (UASGS tool) rather than OpenClaw’s native `web-fetch`
  - `web_search` (UASGS tool)
  - any file/system actions via tool plane rather than native execution

OpenClaw’s SSRF guard remains useful, but UASGS becomes the central policy point.

### 4.4 Context/Memory Plane (Context Engineering, Prompt Injection)

OpenClaw has a memory subsystem (SQLite + embeddings integrations exist in `src/memory/*`).

**Target architecture mapping**
- Any content that will enter an LLM prompt (including retrieved memory) must pass:
  - context admission checks (prompt injection detection / policy)
  - DLP / regulated content classification
  - transformation rules (deny/redact/tokenize), depending on profile (HIPAA/GDPR/etc)

**Minimal change approach**
- Treat “memory retrieval output” as a context contribution:
  - before adding retrieved memory to the prompt, submit it to UASGS Context Admission endpoint
  - only admitted content is eligible to be injected into the prompt context

This can be implemented as a single wrapper function around OpenClaw’s “compose prompt from memory” step, without rewriting the storage backend.

### 4.5 Loop Plane (Non-Intrusive Governance)

OpenClaw (like most agent frameworks) has its own loop, DAG, or FSM controls. For enterprise integration, trying to take over the loop is usually a losing battle.

**Target architecture mapping**
- UASGS should focus on **immutable, external limits** and evidence:
  - max steps per session
  - time budgets / deadlines
  - max tool calls, max model calls
  - max tokens or cost budgets
  - fail-closed policies for regulated profiles

**Key point**
- If every meaningful action (model/tool/context/memory/ingress) is mediated by UASGS, then the loop can remain internal to OpenClaw while still being constrained externally.

## 5. Secrets And DLP: Referential Keys, Vendor-Neutral Language

### 5.1 Replace env API keys with SPIKE references

OpenClaw currently supports resolving API keys from environment and config (see `src/agents/model-auth.ts`). In the enterprise adaptation:
- Operators provision secrets into SPIKE using a CLI (outside of OpenClaw).
- OpenClaw receives only a **reference** (e.g., `spike://...` or an opaque ref token).
- UASGS performs token substitution when calling providers.

This enables “Rotate” from the 3 Rs: short-lived identities and referential secrets.

### 5.2 DLP must not assume “sk-” patterns only

OpenClaw supports keys like `ZAI_API_KEY` (see `src/agents/model-auth.ts`). Enterprises will have many key patterns that do not match `sk-`.

Therefore, DLP rules must be:
- **configurable (RuleOps CRUD)**
- **reviewable and promotable**
- **auditable (active digest/version pinned)**
- **vendor-neutral** (SafeZone can be one implementation option, not a requirement)

## 6. Multi-Channel Adaptation: WhatsApp/Telegram/etc

OpenClaw’s channel system is a great stress-test for the architecture because each channel adds:
- a new ingress path (untrusted)
- new secrets (bot tokens, app tokens)
- new outbound exfil routes
- new operational behaviors (webhooks, polling, socket mode, etc)

**Recommended enterprise posture**
- Treat each channel integration as a managed connector service.
- The agent runtime (OpenClaw) talks only to:
  - UASGS
  - a local channel connector endpoint that is itself governed (tool plane)

This works even on a laptop:
- In Docker Compose: split OpenClaw into a container with no Internet egress; expose only UASGS + connector networks.
- In K8s: enforce with NetworkPolicies (and optionally service mesh egress policies).

## 7. What We Get: Defensibility (STRIDE/PASTA) Without Rewriting OpenClaw

This adaptation yields auditor-friendly properties:
- Centralized enforcement and evidence at UASGS
- Deterministic policy decisions with reason codes
- Clear separation of duties (RACI alignment)
- Secrets rotation and blast-radius reduction
- Production-grade anti-bypass posture in K8s
- A meaningful security uplift even for local/docker usage

## 8. Residual Gaps (Still Acceptable, But Must Be Explicit)

Even after adaptation, some areas remain operational/governance-heavy:
- Channel onboarding approvals (who can talk to the agent, and when)
- Budget governance and exception handling
- Incident response playbooks for denied events, prompt injection detections, and DLP alerts
- Third-party risk management for external model providers

The architecture should provide scaffolding (policy hooks, audit, CLI surfaces), but organizations must supply their governance.

## 9. Concrete “Surgery” Checklist (Port Plan)

This is the minimal work we should expect when porting OpenClaw into our secure environment:

1. **Force model egress through UASGS**
   - Configure OpenClaw provider base URLs to point to UASGS.
   - Remove dependence on raw env keys; use SPIKE references.

2. **Force tool execution through UASGS**
   - Disable native network tools (`web-fetch`, `web-search`) in the runtime profile.
   - Use UASGS tool plane equivalents instead.

3. **Enforce ingress admission**
   - Run channel connectors (Telegram/WhatsApp/etc) outside the agent runtime.
   - All inbound messages go through UASGS Ingress Admission.

4. **Enforce context/memory admission**
   - Gate any memory retrieval inserted into prompts via UASGS Context Admission.

5. **Apply immutable loop limits**
   - Ensure OpenClaw includes session IDs, agent IDs, and trace IDs in all requests to UASGS so external enforcement is reliable.

## 10. Next Steps (In This Repo)

- Create a dedicated backlog epic for “OpenClaw-in-UASGS” adaptation with:
  - walking skeleton (model egress only)
  - channel connector (one channel first, e.g., Telegram)
  - context admission wrapper
  - tool-plane replacements for web tools
  - local compose profile + a multi-day “soak run” with audit review

