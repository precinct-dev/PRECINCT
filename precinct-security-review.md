# Security Review Report — PRECINCT (v2.0)

PRECINCT -- Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools

Scope: `precinct-reference-architecture.md` (dated February 2026). This review focuses on threat coverage, trust boundaries, residual risks, and practicality (developer/user experience) for real-world deployments of MCP-based agent systems.

## Executive Summary

This reference architecture is already strong on **identity**, **authorization**, and **secret non-exfiltration** under an “LLM-as-adversary” assumption, primarily via SPIFFE/SPIRE workload identity, OPA policy enforcement, and SPIKE late-binding secrets. The **PRECINCT Gateway** as a single enforcement point is a good convergence layer, and the **tool registry with hash verification** directly targets MCP-specific attacks (poisoning, rug-pull).

The main gaps are:

1. **Model supply-chain / compromised weights**: integrity and provenance for *model artifacts* (primary LLM and guard models) is not specified, despite relying on them for key security judgments.
2. **Prompt-injection resilience beyond detection**: the design leans on scanning and heuristics; it should add stronger *capability controls* and *context compartmentalization* to reduce dependence on classifier correctness.
3. **Response-side and “legitimate tool” exfiltration**: you call this out as residual risk, but it needs concrete enforcement patterns to move from “medium” to “high” coverage.

The rest of this report lists prioritized findings and concrete mitigation patterns that preserve the document’s core goal: absorb security complexity at the gateway/infra layer without making developers miserable.

## Architecture & Trust Boundaries (as described)

### Primary components
- **Agent workload** (untrusted application plane; may be prompt-injected or malicious).
- **SPIRE** (identity issuance/attestation for workloads).
- **SPIKE** (secrets store issuing *opaque* tokens; gateway redeems).
- **PRECINCT Gateway** (inline enforcement: authn/z, tool verification, DLP, scanning, substitution, audit).
- **MCP servers / tools** (resource servers; can be compromised; may attempt tool poisoning or data exfil).

### Critical trust boundaries
1. **Agent ↔ Gateway**: must assume the agent is adversarial; enforce least privilege and prevent credential exposure.
2. **Gateway ↔ SPIKE**: gateway can redeem secrets; gateway compromise becomes high-impact.
3. **Gateway ↔ Tool Registry / OPA bundles**: policy and allowlist integrity are security-critical supply chain inputs.
4. **Gateway ↔ MCP servers**: tools may be compromised; responses can carry prompt injections and sensitive data.
5. **Model artifacts used by gateway scanning** (Prompt Guard / Llama Guard): if compromised, detection becomes unreliable or adversarial.

## Strengths (What’s already solid)

- **Late-binding secrets** explicitly acknowledges compromised LLM behavior and removes the highest-value exfil target from the model context (see late-binding overview at doc lines 34, 426).
- **Token substitution ordering** is correct (substitution is last, after scanning/policy; doc line 1191).
- **Tool poisoning / rug-pull defenses** via hash verification and allowlist is a strong MCP-specific control (doc lines 807–833).
- **Defense-in-depth** is explicit: fast path for latency, deep path for richer analysis (doc lines 36, 939–1008).
- **Operational and observability posture** is present (metrics/alerts/audit trail; doc lines 1401, 1411, 1444).

## Threat Model Expansion (STRIDE by trust boundary)

This section is meant to make “what can go wrong” mechanically complete, including the **compromised weights** scenario you called out.

### 1) Agent ↔ Gateway
- Spoofing: stolen/misissued SVID; Mitigate with SPIRE attestation hardening + short TTL + node/workload selectors.
- Tampering: agent crafts tool calls that are *policy-compliant* but exfiltrate via allowed channels; Mitigate with egress budgets + destination allowlists + response firewall.
- Repudiation: agent disputes actions; Mitigate with audit chain + decision IDs (you already include OPA decision IDs; doc line 1462).
- Info disclosure: sensitive tool responses returned to agent; Mitigate with response transformation and “handles not raw data”.
- DoS: oversized requests / scanner overload; Mitigate with size limits and rate limiting (documented in middleware chain; doc line 1158).
- Elevation: prompt injection triggers high-risk actions; Mitigate with sync step-up gating + capability tokens + human approval for specific tools.

### 2) Gateway ↔ SPIKE (secret redemption path)
- Spoofing/tampering: fake SPIKE endpoint or MITM; Mitigate with mTLS pinned to SPIFFE IDs (workload identity-to-workload identity).
- Info disclosure: gateway compromise yields secret redemption; Mitigate with minimal gateway surface, strict runtime hardening, and “blast-radius” constraints (destination restrictions already exist in token scopes; doc lines 505–517).
- DoS: SPIKE unavailable leads to fail-closed (good), but requires operational redundancy and clear runbooks.

### 3) Gateway ↔ Policy/Config supply chain (OPA bundles, tool registry, config maps)
- Tampering: malicious policy bundle or registry entry loosens enforcement; Mitigate with signed artifacts, GitOps reviews, and digest logging.
- Repudiation: unclear “which policy allowed this”; Mitigate with policy bundle digest in audit logs (add it).
- DoS: bundle server outage; Mitigate with cached bundles + risk-based degradation (fail closed for critical controls).

### 4) Gateway ↔ MCP servers / external tools
- Tampering: compromised tool returns injected instructions; Mitigate with tool-response normalization + injection scanning + strict output shaping.
- Info disclosure: tool leaks data outside expected scope; Mitigate with per-tool policy + destination allowlists + sandboxing/isolation (gVisor/NetworkPolicy is referenced; doc lines 207, 1338).
- DoS: tool hangs; Mitigate with circuit breakers/timeouts (present in middleware chain; doc line 1188).

### 5) Model artifacts (primary LLM + guard models)
- Tampering (compromised weights): attacker backdoors model behavior (selective non-detection, covert exfil, targeted jailbreak assist).
- Info disclosure: provider logs/prompts retained; Mitigate with local inference for sensitive contexts, redaction before calls, and strict data minimization.
- DoS: guard model returns high false positives; Mitigate with dual-detector strategy and policy-based thresholds.

## Findings (Prioritized)

### Critical

**CRIT-1 — Model artifact integrity (compromised weights) is not addressed**

Impact: If an attacker can replace or tamper with **model weights** (primary LLM, Prompt Guard, Llama Guard), they can (a) evade detection, (b) cause selective false negatives/positives, or (c) embed covert exfil behaviors that appear “normal” to policy/regex-based systems.

Evidence:
- Gateway depends on local/remote guard models for injection/jailbreak classification (doc lines 36, 939–1008).
- Kubernetes mounts model path `/models/prompt-guard-2-86m` from a PVC (doc lines 1305–1335), but does not specify integrity verification of the artifact on disk.

Recommendations (developer-friendly):
1. **Pin + verify guard model artifacts**: store expected `sha256` (or a signature) in config and verify at gateway startup; refuse to start if mismatch for “enforcement-relevant” models.
2. **Signed supply chain**: require cosign/sigstore signatures (containers *and* model artifacts); verify before deploy and at runtime (admission policy).
3. **Isolation**: run guard inference in a separate sandboxed workload with minimal permissions; treat results as advisory unless corroborated by policy signals.
4. **Dual-source validation**: for “block” actions, require either (a) multiple independent detectors agree, or (b) a high-confidence rule + detector agreement (reduces single-model compromise risk).

---

**CRIT-2 — Tool registry verification checks description hash but not schema hash**

Impact: A malicious or compromised MCP server can keep the description stable (hash matches) while changing the **input schema** to coerce unintended tool behavior or enable argument-based injection that bypasses downstream validations.

Evidence:
- Registry includes `InputSchemaHash` (doc lines 807–808) but `VerifyTool` only compares `DescriptionHash` (doc lines 815–833).

Recommendations:
1. Verify **both** description and input schema hashes, and (if available in MCP) any “examples”/metadata fields that can carry instructions.
2. Canonicalize before hashing (normalize whitespace/JSON ordering) to reduce false mismatches and prevent ambiguity.
3. Add a per-tool “allowed argument constraints” layer (JSON Schema + policy), enforced by the gateway after hash verification.

### High

**HIGH-1 — Async deep scanning cannot prevent fast-path prompt injection for high-risk actions**

Impact: An injected agent can execute harmful actions (external send, file write, privileged tool invocation) before async detection completes.

Evidence:
- Deep scanning is explicitly async and “doesn’t block the fast path” (doc lines 36, 950–951, 1400).

Recommendations:
1. Introduce a **sync “step-up” scan** for high-risk tool classes (e.g., `email_send`, `http_request` to external, `file_upload`, `database_write`): block until at least a cheap classifier + policy check completes.
2. Add **capability tokens**: require a gateway-issued, short-lived nonce/capability for “dangerous” actions, minted only after policy checks and (optionally) human approval. This turns prompt injection into “request denied” instead of “detected later”.
3. Separate “alerting scans” (async) from “gating scans” (sync) so operators can tune latency without losing safety.

---

**HIGH-2 — DLP fail-open is risky on egress paths**

Impact: If DLP fails (library error, resource pressure), sensitive data may be sent externally with no barrier.

Evidence:
- Failure mode table sets SafeZone errors to “Fail open (allow)” (doc line 1399).

Recommendations:
1. Make failure mode **policy-driven**: fail-open for low-risk internal tools, but **fail-closed** for external egress and high-risk tools.
2. Emit a “scanner unhealthy” signal that automatically tightens OPA decisions (e.g., disallow external sends until scanner recovers).
3. Prefer “allow but transform”: if you must fail-open, apply conservative response/request transformations (truncate/redact) and require human approval for external destinations.

---

**HIGH-3 — Response-side protections are acknowledged but not concretely designed**

Impact: Even with late-binding secrets, tools can return sensitive data to the agent, and the agent can then exfiltrate it using legitimate channels.

Evidence:
- Residual risk explicitly calls out “Response data exfiltration” and recommends “Response transformation” (doc lines 1506–1511).

Recommendations (pragmatic patterns):
1. **Response firewall**: classify tool responses and enforce “max classification” rules (e.g., agents authorized to read `sensitive` cannot send `sensitive` externally).
2. **Minimize return-to-LLM**: for high-risk tools, return *handles* (references) instead of raw data; allow the gateway to stream/redact selectively.
3. **Safe summaries**: for large/sensitive responses, transform into structured summaries with citations/IDs and omit raw values unless explicitly approved.

### Medium

**MED-1 — Policy and allowlist supply chain integrity is under-specified**

Impact: If attackers can tamper with OPA bundles, tool registry config, or gateway configuration, they can silently loosen enforcement.

Evidence:
- Architecture references “OPA Bundle Server” and Tool Registry as control-plane inputs (doc lines 1017, 1300), but does not specify signing/attestation/access controls for those artifacts.

Recommendations:
1. Sign OPA bundles and tool registry artifacts; verify signatures in the gateway before applying updates.
2. Enforce least-privilege write access (GitOps + review; break-glass only).
3. Add “policy provenance” to audit logs (bundle digest, registry digest).

---

**MED-2 — “Tool Registry stale → cached (warn)” can become a persistence window**

Impact: If the registry is stale and a tool is compromised, continuing to use cached allowlist entries can extend exposure.

Evidence:
- Failure mode accepts stale tool registry as “Use cached (warn)” (doc line 1401).

Recommendations:
1. Make staleness tolerance tool/risk-level dependent: allow cache for low-risk internal tools; fail closed for high-risk tools after a short grace period.
2. Alert on staleness and automatically restrict risky capabilities until freshness is restored.

---

**MED-3 — Session exfiltration detection is heuristic and may be easy to evade**

Impact: Attackers can delay exfil steps beyond the lookback window, use multiple low-volume sends, or stage data in intermediate tools.

Evidence:
- Session logic (example) checks only a small recent window (doc lines 861–903).

Recommendations:
1. Track **data lineage signals** (classification labels, sources, destinations) across the whole session, not just the last N actions.
2. Add **egress budgets** per session (bytes, requests, entropy) and require step-up for anomalies.
3. Record and enforce “allowed destination sets” at the gateway, not in agent prompt logic.

### Low

**LOW-1 — Regex-based poisoning detection is brittle**

Impact: Regex rules can be bypassed with encoding/obfuscation and can also false-positive on legitimate tool docs.

Evidence:
- Regex poisoning patterns are used in both OPA and gateway examples (doc lines 666–683, 848–857).

Recommendations:
1. Normalize tool descriptions before scanning (strip HTML comments, decode entities, collapse whitespace).
2. Prefer a **structural allowlist**: tool descriptions should be treated as untrusted metadata; gate on registry hashes and explicit per-tool policy, not “detected safe text”.

## Prompt Injection Hardening (beyond scanning)

The document already includes prompt-injection detection (regex + deep scans). The bigger win is to reduce how much the system *depends* on detection correctness by adding deterministic interlocks.

1. **Canonical tool catalog (registry-served)**
   - Instead of passing through tool server–provided descriptions/schemas, have the gateway serve the agent a **sanitized, canonical** tool catalog derived from the registry.
   - The gateway can still hash-verify what the server claims to implement, but the agent shouldn’t need to ingest arbitrary server-supplied prose (the primary poisoning channel).

2. **Strict argument validation and normalization**
   - Enforce JSON Schema (and additional policy constraints) on tool arguments at the gateway, including “no extra fields”, tight max lengths, and allowlisted destination patterns.
   - Normalize/encode dangerous fields (URLs, file paths) so the model can’t smuggle data in unexpected parts of the request.

3. **Capability-based actions for high-risk tools**
   - For tools that can exfiltrate or mutate state, require a short-lived, gateway-minted capability token (and optionally human approval) attached to the request.
   - This turns prompt injection into “missing capability → denied”, even if the model is fully compromised.

4. **Tool-response shaping**
   - Wrap tool results into a standard “untrusted data envelope” and optionally strip/escape markup to reduce instruction-like payloads reaching the agent.
   - Pair this with response firewall rules (classification + destinations) so even if the agent is coerced, it can’t legally route sensitive data outward.

## Additional Threat Vectors to Add Explicitly (Suggested coverage additions)

These aren’t fully covered today, or are only implied:

1. **Compromised primary model provider** (prompt/response retention, cross-tenant leakage, insider access): mitigate with local models for sensitive workloads and strict redaction before model calls.
2. **Memory systems / long-term context** (vector DB, scratchpads): even if v2.0 targets no long-term memory (doc line 30), production agents often add it. Add guidance for memory write/read scanning, per-item TTL, and provenance.
3. **Authorization delegation chains**: add explicit “actor vs. subject” claims and enforce them in OPA to prevent confused deputy across multi-hop agent calls.

## Developer Experience (How to hide complexity upstream)

To keep this powerful architecture from becoming “security theatre that devs hate”, package it as a **golden path**:

1. **Gateway-first SDK**: one client wrapper that routes MCP traffic through the gateway by default, with safe defaults and minimal config.
2. **Tool onboarding pipeline**: a CLI/workflow that (a) computes canonical tool/schema hashes, (b) registers tools with risk/classification, (c) opens a PR to the tool registry + OPA data, (d) runs a lightweight “tool poisoning lint”.
3. **Policy templates**: ship baseline bundles for common tool types (DB read/write, HTTP egress, email/slack, file I/O) so teams only fill in resources/destinations.
4. **Progressive enforcement**: start in “observe” mode (log/alert), then tighten to “block” for a small set of high-risk tools first.

## Recommended Hardening Roadmap (low-friction sequencing)

1. **Close the known correctness gaps**
   - Verify tool **schema hash** (CRIT-2).
   - Add **sync step-up gating** for high-risk tools (HIGH-1).
   - Make DLP failure handling **risk-based** (HIGH-2).

2. **Reduce dependence on LLM classifiers**
   - Implement **capability tokens** and “deny-by-default” for exfil/mutation tools.
   - Serve a **canonical tool catalog** from the registry (prompt-injection reduction).

3. **Implement response controls**
   - Response firewall + “handles not raw” for sensitive tools (HIGH-3).
   - Session-wide budgets and lineage tracking (MED-3).

4. **Model supply-chain / compromised weights**
   - Start with simple, effective controls: **pinned hashes + startup verification** for local models.
   - Then move to signed artifacts + cluster admission verification + (optionally) attestation for high-sensitivity deployments.

## External Threat Validation: Agents of Chaos

### Citation

Shapira, N., Bitton, R., Fordham, T., Mimran, D., Moshkowich, D., Nassi, B., Elovici, Y. (2026). *Agents of Chaos: Exploring Malicious Agentic AI*. arXiv:2602.20021v1.

### Overview

The Agents of Chaos paper presents 16 case studies of real-world threat scenarios against agentic AI systems. These case studies provide external validation that PRECINCT's threat model and control coverage address documented attack patterns, not merely theoretical risks.

### Case Study to STRIDE Mapping

The following maps each of the 16 case studies from the Agents of Chaos paper to STRIDE threat categories and identifies PRECINCT controls that provide coverage:

#### Spoofing

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #8 (Identity spoofing via authority confusion) | Agent impersonates a higher-privilege principal or confuses identity boundaries | SPIFFE/SPIRE workload identity (middleware step 3), Principal Hierarchy with SPIFFE-to-role resolution |
| #11 (Privilege confusion across task contexts) | Agent uses elevated context from one task to act in another, spoofing authorization level | SPIFFE/SPIRE per-workload identity isolation, OPA policy with task-scoped claims (middleware step 6) |

#### Tampering

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #2 (Conversation history manipulation) | Agent rewrites or suppresses its own action history to hide malicious behavior | Hash-chained audit logging (middleware step 4) provides tamper-evident history independent of agent-controlled context |
| #9 (Misdirection via false tool outputs) | Agent or compromised tool returns fabricated results to mislead downstream decisions | Tool registry hash verification (middleware step 5), response firewall with output validation, deep scan (middleware step 10) |
| #10 (Mutable external data source / rug-pull) | External data source modified after initial verification to inject malicious content | Tool registry hash verification (middleware step 5), Data Source Integrity with MutablePolicy enforcement |

#### Repudiation

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #2 (Conversation history manipulation) | Agent rewrites or suppresses its own action history to deny accountability | Hash-chained audit logging (middleware step 4), structured JSON audit with trace/session/decision IDs; gateway-side audit is independent of agent-controlled history |
| #7 (Memory destruction / gaslighting) | Agent deletes or alters shared memory to deny prior actions occurred | Hash-chained audit logging (middleware step 4), immutable audit trail with cryptographic integrity verification (`middleware/audit_verify.go`) |

#### Information Disclosure

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #3 (SSN in email body) | Sensitive PII embedded in outbound agent communication | DLP scanner (middleware step 7), Channel Mediation with content routing through middleware |
| #13 (Side-channel leakage via timing or metadata) | Sensitive information leaked through timing patterns, metadata, or observable side effects | Rate limiting normalization (middleware step 1), structured response shaping, audit log access controls |
| #14 (Data exfiltration) | Agent exfiltrates data through side channels or legitimate tool responses | Response firewall, late-binding secret substitution, egress budgets |
| #15 (Out-of-band command injection via steganography) | Hidden instructions embedded in images, PDFs, or other binary payloads bypass text-based scanning | Deep scan path (middleware step 10) with multi-modal content analysis, strict input validation and content-type enforcement |

#### Denial of Service

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #4 (Instruction loops) | Agent trapped in infinite loop consuming resources | Rate limits and circuit breakers, immutable run envelopes with step/time/cost bounds |
| #5 (Resource exhaustion) | Agent consumes excessive compute, memory, or API quota | Rate limiting (middleware step 1), provider budget policy, Channel Mediation for unbounded consumption |
| #16 (Long-horizon persistence) | Agent plants triggers or maintains hidden state for future exploitation, sustaining resource drain over time | Session context tracking (middleware step 8) with TTL enforcement, immutable run envelopes with step/time/cost bounds, audit trail anomaly detection |

#### Elevation of Privilege

| Case Study | Threat Description | PRECINCT Control |
|---|---|---|
| #1 (Progressive destruction) | Agent gradually escalates actions from benign to destructive | Escalation Detection with EscalationScore formula, Irreversibility Gating with ClassifyActionDestructiveness |
| #6 (Cross-agent prompt injection via shared memory) | One agent poisons shared context to hijack another agent's actions with elevated privileges | Input sanitization and injection scanning (middleware steps 7, 10), per-workload SPIFFE identity isolation, OPA policy enforcement per principal |
| #7 (Concession accumulation) | Agent incrementally extracts permissions through repeated small requests | Session context tracking (middleware step 8), Escalation Detection with threshold alerts (Warning=15/Critical=25/Emergency=40) |
| #11 (Privilege confusion across task contexts) | Agent carries over elevated permissions from one task context to act in another | OPA policy with task-scoped claims (middleware step 6), per-request authorization evaluation, SPIFFE identity scoping |
| #12 (Gradual policy erosion) | Agent makes incremental exceptions to security policies, accumulating concessions until controls are effectively bypassed | Escalation Detection (middleware step 8) with cumulative scoring, immutable OPA policy bundles with signed artifacts, audit trail for policy override patterns |

### Threat Coverage Matrix (Updated)

The following matrix summarizes PRECINCT control coverage against the threat categories validated by the Agents of Chaos case studies. Controls marked with (NEW) were added in response to this external validation.

| STRIDE Category | Case Studies | Control | Middleware Step | Evidence |
|---|---|---|---|---|
| Spoofing | #8 | SPIFFE/SPIRE workload identity | Step 3 | `middleware/spiffe_auth.go` |
| Spoofing | #8 | Principal Hierarchy (NEW) | Step 3 | SPIFFE-to-role resolution, X-Precinct-Principal-Level header |
| Spoofing | #11 | Per-workload identity isolation | Step 3 | SPIFFE/SPIRE task-scoped claims, OPA policy enforcement |
| Tampering | #2 | Hash-chained audit logging | Step 4 | `middleware/audit.go`, tamper-evident history |
| Tampering | #9 | Response validation + deep scan | Steps 5, 10 | Tool registry hash verification, output validation |
| Tampering | #10 | Tool registry hash verification | Step 5 | `middleware/tool_registry.go` |
| Tampering | #10 | Data Source Integrity (NEW) | Step 5 | DataSourceDefinition struct, MutablePolicy enforcement |
| Repudiation | #2 | Hash-chained audit logging | Step 4 | `middleware/audit.go`, gateway-side audit independent of agent history |
| Repudiation | #7 | Immutable audit trail | Step 4 | `middleware/audit_verify.go`, cryptographic integrity verification |
| Info Disclosure | #3 | DLP scanner | Step 7 | `middleware/dlp.go` |
| Info Disclosure | #3 | Channel Mediation (NEW) | Steps 7, 10 | Ed25519 webhook verification, content routing |
| Info Disclosure | #13 | Rate limiting normalization | Step 1 | Timing side-channel mitigation, structured response shaping |
| Info Disclosure | #14 | Response firewall + egress budgets | Steps 7, 10 | Late-binding secret substitution, DLP scanner |
| Info Disclosure | #15 | Deep scan with content analysis | Step 10 | Multi-modal content analysis, content-type enforcement |
| DoS | #4, #5 | Rate limits and circuit breakers | Step 1 | Rate limiter middleware |
| DoS | #4, #5 | Channel Mediation (NEW) | Steps 7, 10 | Unbounded consumption prevention |
| DoS | #16 | Session TTL + run envelopes | Step 8 | Session context tracking, step/time/cost bounds |
| EoP | #1 | Irreversibility Gating (NEW) | Step 9 | ClassifyActionDestructiveness, automatic step-up |
| EoP | #1, #7 | Escalation Detection (NEW) | Step 8 | EscalationScore (Impact x (4 - Reversibility)), thresholds |
| EoP | #6 | Input sanitization + identity isolation | Steps 7, 10, 3 | Injection scanning, per-workload SPIFFE identity |
| EoP | #7 | Session context tracking | Step 8 | `middleware/session_context.go` |
| EoP | #11 | Task-scoped OPA policy | Step 6 | Per-request authorization, SPIFFE identity scoping |
| EoP | #12 | Cumulative escalation scoring | Step 8 | Immutable OPA bundles, audit trail for policy overrides |

## Suggested Next Step

If you want, I can propose a concrete “v2.1” patch to `precinct-reference-architecture.md` that adds:
- a dedicated “Model Supply Chain / Weight Integrity” subsection,
- a “sync step-up gating” pattern for high-risk tools,
- explicit schema hash verification in the Tool Registry section,
- and a response firewall design (moving the residual-risk item toward implementable controls).
