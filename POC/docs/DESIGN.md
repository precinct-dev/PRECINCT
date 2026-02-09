# DESIGN.md -- Phase 2: Agentic AI Security Reference Architecture POC

**Version:** 1.0
**Date:** 2026-02-06
**Author:** Designer (D&F Phase)
**Status:** Draft for BLT Review

---

## 1. User Personas

Phase 2 has four distinct user personas. Each interacts with different surfaces of the system and has different definitions of success.

### 1.1 Persona: Ava -- OSS Developer / Researcher

**Background:** Software engineer or security researcher evaluating the reference architecture. May work at a startup, academic lab, or enterprise R&D team. Has Docker experience. May or may not have security domain expertise.

**Goals:**
- Clone the repo and have a running system quickly
- Understand what security controls are operating and how
- Extend or adapt patterns for their own use case

**Frustrations:**
- Complex setup processes with unclear prerequisites
- Silent failures where "something is off but nothing tells me what"
- Documentation that assumes deep security knowledge

**Touchpoints:** Git clone, CLI setup, `make` commands, reading code, running E2E tests, Phoenix dashboard

**Success metric:** Running and understanding the system within 30 minutes

### 1.2 Persona: Eliana -- Enterprise Security Evaluator

**Background:** Security architect, CISO staff, or compliance officer at a regulated organization. Evaluates tools for SOC 2, ISO 27001, GDPR, and CCPA posture. May not write code. Needs evidence, not promises.

**Goals:**
- Determine whether the architecture meets compliance requirements
- Generate evidence that can be handed to an auditor or ingested by a compliance tool
- Understand the threat model and what is (and is not) covered

**Frustrations:**
- Having to read code to understand compliance posture
- Reports that require manual mapping to frameworks
- Unclear boundary between "what the gateway covers" and "what you must handle yourself"

**Touchpoints:** Compliance report output (XLSX/CSV/PDF), E2E test results, architecture documentation, control mapping

**Success metric:** Producing an auditor-ready compliance package in one command

### 1.3 Persona: Marcus -- Agent Developer

**Background:** Building AI agents using frameworks like PydanticAI, DSPy, LangGraph, CrewAI, or raw HTTP. Needs to connect agents to the MCP gateway with minimal boilerplate. Cares about DX, not security internals.

**Goals:**
- Connect an agent to the gateway in under 15 minutes
- Understand what the gateway expects (headers, payload format, error codes)
- Handle denials gracefully without crashing the agent

**Frustrations:**
- Needing to implement 100+ lines of boilerplate per agent (as seen in Phase 1 agents)
- Inconsistent error response formats across middleware layers
- Unclear which headers are required vs optional

**Touchpoints:** SDK/client library, error responses, gateway API surface, agent code, integration guide

**Success metric:** Working agent-gateway integration in under 20 lines of framework-specific code

### 1.4 Persona: Ops -- Operations / Platform Engineer

**Background:** Manages the running system. Monitors health, investigates incidents, tunes security posture. May be the same person as Ava in smaller teams.

**Goals:**
- See at a glance whether the system is healthy
- Trace a single request through all 13 middleware layers
- Identify bottlenecks, failures, and security events quickly

**Frustrations:**
- Empty dashboards (Phase 1 gap -- Phoenix running but no traces)
- Having to grep audit logs instead of using a visual tool
- No correlation between agent identity and the security decisions made about their requests

**Touchpoints:** Phoenix/OTel dashboard, audit logs, health endpoints, alerting

**Success metric:** Diagnosing a security denial within 2 minutes of it occurring

---

## 2. Design Principles

These principles guide every design decision in Phase 2. They are ordered by priority when in conflict.

### P1: No Silent Degradation

If a security control is disabled, degraded, or unavailable, the system MUST tell the user explicitly. This applies to:
- CLI setup output (what is enabled, what is not, and why)
- Runtime error responses (which middleware blocked and why)
- Observability (a missing span is a bug, not a feature)

**Rationale:** The business owner stated: "never silently degrade security posture." A system that quietly drops protections is worse than one that loudly refuses to start.

### P2: Actionable Errors

Every error response must tell the recipient what happened, why, and what they can do about it. A developer receiving a 403 should know which middleware blocked them and what to change. An operator seeing a failed span should know which service is responsible.

**Rationale:** Phase 1 revealed inconsistent error formats. DLP returns `"Forbidden: Request contains sensitive credentials"` (plain text), OPA returns `"Policy denied: <reason>"` (plain text), and step-up gating returns structured JSON with `risk_breakdown`. Developers writing integration code must handle all three formats, which is unnecessarily complex.

### P3: Progressive Disclosure

Simple things should be simple. Complex things should be possible. The CLI setup should have smart defaults for Ava and deep configuration for Eliana. The SDK should have a one-liner for Marcus and extensibility for Ops.

**Rationale:** Three audiences with different depth needs. A CLI that asks 47 questions before starting is as bad as one that silently picks insecure defaults.

### P4: Evidence Over Assertion

Every compliance claim must point to specific, verifiable evidence -- an audit log entry, a policy configuration, a test result. "We do DLP scanning" is an assertion. "Audit event #47 shows AWS key AKIA... blocked at 2026-02-06T14:23:01Z by DLP middleware with flags [blocked_content]" is evidence.

### P5: Framework Independence

Agent developers should not be forced into a specific framework. The gateway speaks MCP JSON-RPC over HTTP. The SDK provides convenience, not lock-in. A `curl` command should always work.

### P6: Changeability Through Clean Boundaries

Design for the reality that requirements will change. Phase 3 will likely add streaming MCP, plugin ecosystems, and new compliance frameworks. The interfaces we define now (error format, SDK contract, report schema) become the contracts that either enable or prevent change.

---

## 3. User Journey Maps

### 3.1 Ava's Journey: Git Clone to First Request

```
+------------------+     +----------------+     +------------------+     +-----------------+
| 1. git clone     | --> | 2. make setup  | --> | 3. CLI guided    | --> | 4. make up      |
|    + cd POC      |     |    (prereq     |     |    config        |     |    (services     |
|                  |     |     check)     |     |                  |     |     start)       |
+------------------+     +----------------+     +------------------+     +-----------------+
                                                       |                        |
                                                       v                        v
                                                +------------------+     +-----------------+
                                                | 3a. Security     |     | 5. E2E smoke    |
                                                |     posture      |     |    test passes   |
                                                |     summary      |     |    automatically |
                                                +------------------+     +-----------------+
                                                                                |
                                                                                v
                                                                         +-----------------+
                                                                         | 6. First manual |
                                                                         |    request via  |
                                                                         |    curl example |
                                                                         +-----------------+
```

**Step 2: Prerequisite Check.** Before anything else, the CLI verifies that required tools exist: Docker, Docker Compose, Go (for development), and optional tools (cosign, syft, opa). Missing required tools produce clear install instructions. Missing optional tools produce informational messages about what functionality is reduced.

**Step 3: Guided Configuration.** The CLI presents a series of questions with defaults. Each question explains the security consequence of the choice. The flow is designed so that pressing Enter at every prompt produces a secure, working configuration.

**Step 3a: Security Posture Summary.** After configuration, before starting services, the CLI prints a summary table showing what is enabled and what is not. This is the "informed consent" moment.

**Step 5: Automated Smoke Test.** After services start, the CLI automatically runs a minimal smoke test (one happy-path request, one denial) and reports results. The user does not need to find and run test scripts manually.

### 3.2 Eliana's Journey: Compliance Evidence Generation

```
+------------------+     +------------------+     +------------------+
| 1. make          | --> | 2. Report        | --> | 3. Auditor       |
|    compliance-   |     |    generation    |     |    receives      |
|    report        |     |    (automated)   |     |    package       |
+------------------+     +------------------+     +------------------+
       |                        |                        |
       v                        v                        v
+--------------+         +--------------+         +--------------+
| Runs E2E     |         | Processes    |         | XLSX: per-   |
| tests as     |         | audit logs   |         |   control    |
| evidence     |         | for evidence |         |   evidence   |
| collection   |         | extraction   |         |              |
+--------------+         +--------------+         | CSV: machine |
                                                  |   parseable  |
                                                  |              |
                                                  | PDF: exec    |
                                                  |   summary    |
                                                  +--------------+
```

**One command, three outputs.** The compliance report runs E2E tests, collects audit evidence, and maps controls to framework requirements. The output is self-contained: no need to cross-reference external systems.

### 3.3 Marcus's Journey: Agent Integration

```
+------------------+     +------------------+     +------------------+
| 1. Install SDK   | --> | 2. Configure     | --> | 3. Call tools    |
|    (pip/go get)  |     |    gateway URL   |     |    through       |
|                  |     |    + SPIFFE ID   |     |    gateway       |
+------------------+     +------------------+     +------------------+
                                                         |
                                                         v
                                                  +------------------+
                                                  | 4. Handle        |
                                                  |    denials       |
                                                  |    (structured)  |
                                                  +------------------+
```

**Today (Phase 1 -- 100+ lines per agent):**
Both the DSPy and PydanticAI agents implement identical `GatewayClient`, `GatewayDenial`, and `ToolCallResult` classes (approximately 120 lines each). This is pure boilerplate duplication.

**Phase 2 target (under 20 lines):**
A shared SDK extracts the common patterns and exposes a clean interface. The agent developer writes only the agent-specific logic.

### 3.4 Ops's Journey: Request Investigation

```
+------------------+     +------------------+     +------------------+
| 1. See alert     | --> | 2. Open trace    | --> | 3. Drill into    |
|    or anomaly    |     |    in Phoenix    |     |    specific      |
|                  |     |                  |     |    middleware     |
+------------------+     +------------------+     +------------------+
       |                        |                        |
       v                        v                        v
+--------------+         +--------------+         +--------------+
| Health       |         | 13-span      |         | Per-span     |
| endpoint     |         | waterfall    |         | attributes:  |
| shows        |         | shows full   |         | decision,    |
| circuit      |         | middleware   |         | risk score,  |
| state        |         | chain timing |         | DLP flags,   |
+--------------+         +--------------+         | policy       |
                                                  +--------------+
```

---

## 4. Interface Designs

### 4.1 CLI Setup Experience

The CLI setup command (`make setup` or a standalone `./setup.sh`) is the entry point for all personas. It follows an interactive, wizard-style flow with smart defaults.

#### 4.1.1 Prerequisite Check Output

```
Agentic AI Security Gateway -- Setup
=====================================

Checking prerequisites...

  [OK]   Docker          25.0.3
  [OK]   Docker Compose  2.24.1
  [OK]   Go              1.23.4
  [--]   cosign          not found (optional: container image signing, K8s only)
  [--]   syft            not found (optional: SBOM generation)
  [OK]   opa             0.62.0

Prerequisites met. Proceeding with configuration.
```

`[OK]` = installed and version acceptable.
`[--]` = optional, not found, with explanation of what functionality is affected.
`[FAIL]` = required, not found, with install instructions specific to the detected OS.

#### 4.1.2 Guided Configuration Questions

Questions are presented one at a time. Each includes a default, a brief explanation, and the security consequence. The format is:

```
Deep Scan (LLM-based content analysis)
---------------------------------------
The deep scan uses a guard model (Prompt Guard 2 via Groq) to detect
prompt injection and jailbreak attempts in tool call payloads.

If the guard model is unavailable (rate-limited, network issue, or no API key),
the gateway must decide whether to:

  [1] Block the request (fail-closed) -- more secure, may cause false denials
  [2] Allow the request (fail-open)   -- less secure, no disruption

This choice is made now and applied at startup. It can be changed later
by editing .env and restarting.

Deep scan fallback policy [1]:
```

```
Groq API Key (for deep scan)
-----------------------------
Deep scan requires a Groq API key for the Prompt Guard 2 model.

Without a key, deep scan will be DISABLED entirely.
Get a free key at: https://console.groq.com/keys

GROQ_API_KEY [press Enter to skip]:
```

```
Session Persistence (KeyDB)
----------------------------
KeyDB stores session context across HTTP requests, enabling cross-request
exfiltration detection and distributed rate limiting.

Without KeyDB, session context is per-request only. An attacker could
read secrets in request 1 and exfiltrate in request 2 without detection.

Enable KeyDB for session persistence? [Y/n]:
```

#### 4.1.3 Security Posture Summary

After all questions are answered, before starting services:

```
Security Posture Summary
========================

Control                    Status      Detail
---------------------------------------------------------------------------
SPIFFE Identity (mTLS)     ENABLED     Dev mode (header-based attestation)
OPA Authorization          ENABLED     8 policy rules, 67 Rego tests pass
DLP Scanning               ENABLED     Credentials: fail-closed, PII: audit-only
Deep Scan (Guard Model)    DISABLED    No GROQ_API_KEY provided
                                       Fallback: fail-open (requests allowed)
Session Persistence        ENABLED     KeyDB at localhost:6379
Rate Limiting              ENABLED     100 req/min per agent, burst 20
Circuit Breaker            ENABLED     Threshold: 5 failures, reset: 30s
Token Substitution         ENABLED     SPIKE Nexus at localhost:8443
Tool Registry              ENABLED     5 tools registered, SHA-256 verified
Audit Logging              ENABLED     Hash-chained JSONL at /tmp/audit.jsonl
Observability              ENABLED     OTel -> Phoenix at localhost:6006

WARNINGS:
  * Deep scan is DISABLED. Prompt injection detection relies on DLP regex only.
    To enable, set GROQ_API_KEY in .env and re-run setup.
  * SPIFFE is in DEV MODE. For production, enable mTLS with real SPIRE SVIDs.
    See docs/spiffe-setup.md for instructions.

Proceed with this configuration? [Y/n]:
```

The summary uses three states:
- `ENABLED` -- control is active and operational
- `DISABLED` -- control is off, with the reason and consequence
- `DEGRADED` -- control is active but operating in a reduced mode (e.g., fail-open)

Warnings are listed separately and call out specific actions the user can take to improve posture.

#### 4.1.4 Post-Startup Smoke Test

```
Starting services...
  [OK] spire-server     healthy (8s)
  [OK] spire-agent      healthy (12s)
  [OK] keydb            healthy (3s)
  [OK] spike-nexus      healthy (6s)
  [OK] otel-collector   running (2s)
  [OK] phoenix          healthy (5s)
  [OK] gateway          healthy (4s)

Running smoke test...
  [PASS] Happy path:    read tool -> 502 (upstream not started, middleware chain OK)
  [PASS] Policy denial: bash tool -> 403 (tool_not_authorized)
  [PASS] DLP detection: AWS key  -> 403 (blocked_content)
  [PASS] Audit chain:   3 events, hash chain intact
  [PASS] Health:        circuit_breaker: closed

Setup complete. Gateway is running at http://localhost:9090

Next steps:
  * Phoenix dashboard:     http://localhost:6006
  * Run full E2E tests:    make test-e2e
  * Generate compliance:   make compliance-report
  * Connect an agent:      See docs/agent-integration.md
  * Try it with curl:

    curl -s -X POST http://localhost:9090 \
      -H "Content-Type: application/json" \
      -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
      -H "X-Session-ID: demo-session-1" \
      -d '{"jsonrpc":"2.0","method":"read","params":{"file_path":"go.mod"},"id":1}'
```

---

### 4.2 Compliance Report Design

#### 4.2.1 Report Generation Flow

```
make compliance-report
  |
  +--> 1. Run E2E test suite (collect evidence)
  +--> 2. Parse audit log (extract control activations)
  +--> 3. Read policy configs (OPA rules, tool registry, DLP patterns)
  +--> 4. Map controls to frameworks (SOC 2, ISO 27001, CCPA, GDPR)
  +--> 5. Generate output files:
           reports/compliance-YYYY-MM-DD/
             compliance-report.xlsx
             compliance-report.csv
             compliance-summary.pdf
             evidence/
               audit-log-excerpt.jsonl
               e2e-test-results.txt
               policy-configs/
                 opa-policy.rego
                 tool-registry.yaml
                 risk-thresholds.yaml
```

#### 4.2.2 XLSX/CSV Schema

The compliance report maps each control to each framework. One row per control-framework combination.

| Column | Description | Example |
|--------|-------------|---------|
| `control_id` | Internal identifier | `GW-AUTH-001` |
| `control_name` | Human-readable name | `Agent Identity Verification (SPIFFE/mTLS)` |
| `control_description` | What the control does | `Verifies agent identity via SPIFFE SVID before...` |
| `framework` | Compliance framework | `SOC 2 Type II` |
| `framework_requirement` | Specific requirement | `CC6.1 Logical access security` |
| `status` | Implementation status | `Implemented`, `Partial`, `Documented Only` |
| `evidence_type` | Type of evidence | `Audit Log`, `Configuration`, `Test Result` |
| `evidence_reference` | Pointer to evidence | `audit-log-excerpt.jsonl:line 47` |
| `evidence_description` | What the evidence shows | `Audit event shows SPIFFE ID verified for agent...` |
| `test_result` | E2E test outcome | `PASS (scenario_a, check A3)` |
| `implementation_notes` | Technical details | `SPIRE server + agent with Docker attestor...` |
| `limitations` | Known gaps or caveats | `Dev mode uses header injection; prod requires mTLS` |
| `recommendation` | Auditor guidance | `For production: enable mTLS mode, configure SPIRE...` |

#### 4.2.3 PDF Executive Summary

The PDF is a 2-4 page document designed for executives and auditors who will not read the XLSX.

**Page 1: Cover + Summary**
- Architecture name, version, date
- Overall compliance posture (e.g., "38/42 controls implemented, 4 documented-only")
- Framework coverage percentages

**Page 2: Control Matrix**
- Heat map: rows = control areas, columns = frameworks
- Green = implemented with evidence, Yellow = partial, Gray = documented-only
- Each cell references the XLSX row number for drill-down

**Page 3: Evidence Highlights**
- 5-8 exemplary audit log entries showing key controls in action
- Redacted to remove any sensitive data while preserving the structure

**Page 4: Limitations and Recommendations**
- Honest enumeration of what is NOT covered
- Clear distinction between gateway controls and infrastructure controls
- Specific recommendations for each "Partial" or "Documented Only" control

#### 4.2.4 Control Taxonomy

Controls are organized by area. Each area maps to one or more middleware layers.

| Control Area | Gateway Middleware | Control IDs |
|-------------|-------------------|-------------|
| Identity | SPIFFE Auth (step 3) | `GW-AUTH-001` through `GW-AUTH-003` |
| Authorization | OPA Policy (step 6) | `GW-AUTHZ-001` through `GW-AUTHZ-004` |
| Data Protection | DLP (step 7), Token Sub (step 13) | `GW-DLP-001` through `GW-DLP-005` |
| Content Security | Deep Scan (step 10), Step-Up (step 9) | `GW-SCAN-001` through `GW-SCAN-003` |
| Audit | Audit Logging (step 4) | `GW-AUDIT-001` through `GW-AUDIT-004` |
| Secrets | Token Substitution (step 13), SPIKE | `GW-SEC-001` through `GW-SEC-003` |
| Transport | mTLS | `GW-TRANS-001`, `GW-TRANS-002` |
| Availability | Rate Limit (step 11), Circuit Breaker (step 12) | `GW-AVAIL-001` through `GW-AVAIL-003` |
| Session | Session Context (step 8) | `GW-SESS-001` through `GW-SESS-003` |
| Supply Chain | Cosign, SBOM | `GW-SC-001` through `GW-SC-003` |

---

### 4.3 Observability Design

#### 4.3.1 Trace Structure

Each request through the gateway produces a single parent span with 13 child spans (one per middleware layer). Cross-service spans link the agent, gateway, MCP server, and SPIKE Nexus into a single distributed trace.

```
[Agent Span]
  |
  +-- [Gateway: request_size_limit]      step 1    0.1ms
  +-- [Gateway: body_capture]            step 2    0.3ms
  +-- [Gateway: spiffe_auth]             step 3    0.2ms
  |     attributes: spiffe_id, auth_mode
  +-- [Gateway: audit_log]               step 4    0.5ms
  |     attributes: session_id, decision_id, prev_hash
  +-- [Gateway: tool_registry_verify]    step 5    0.4ms
  |     attributes: tool_name, hash_verified, registry_digest
  +-- [Gateway: opa_policy]              step 6    1.2ms
  |     attributes: decision_id, allowed, reason, bundle_digest
  +-- [Gateway: dlp_scan]                step 7    0.8ms
  |     attributes: has_credentials, has_pii, flags[]
  +-- [Gateway: session_context]         step 8    0.3ms
  |     attributes: session_id, risk_score, action_count
  +-- [Gateway: step_up_gating]          step 9    2.1ms
  |     attributes: gate, total_score, impact, reversibility,
  |                 exposure, novelty, guard_result
  +-- [Gateway: deep_scan_dispatch]      step 10   0.1ms
  |     attributes: dispatched, async
  +-- [Gateway: rate_limit]              step 11   0.1ms
  |     attributes: remaining, limit, burst
  +-- [Gateway: circuit_breaker]         step 12   0.1ms
  |     attributes: state (closed/open/half-open)
  +-- [Gateway: token_substitution]      step 13   0.3ms
  |     attributes: tokens_substituted, spike_ref_count
  +-- [Gateway: proxy -> MCP Server]
  |     +-- [MCP Server: tool_execution]
  |           +-- [SPIKE Nexus: secret_retrieval]
  +-- [Gateway: response_firewall]
        attributes: handles_created, data_handleized
```

#### 4.3.2 Key Dashboard Views (Phoenix)

**View 1: Request Waterfall (per-request)**
- Standard OTel waterfall showing all 13 middleware spans plus proxy and response
- Each span shows timing, status (ok/error), and key attributes
- Color coding: green = passed, red = blocked, yellow = flagged (audit-only)

**View 2: Security Event Feed**
- Filtered view of spans where a security decision was made
- Columns: timestamp, agent SPIFFE ID, tool, middleware, decision, reason
- Sortable by severity (deny > flag > allow)

**View 3: Middleware Chain Health**
- Aggregate view showing P50/P95/P99 latency per middleware layer
- Identifies which middleware is the latency bottleneck
- Circuit breaker state visible as a status indicator

**View 4: Agent Activity**
- Grouped by SPIFFE ID (agent identity)
- Shows request volume, denial rate, risk score distribution per agent
- Useful for identifying compromised or misbehaving agents

#### 4.3.3 Span Attribute Schema

All gateway spans MUST include these attributes:

| Attribute | Type | Example | Purpose |
|-----------|------|---------|---------|
| `mcp.gateway.step` | int | `7` | Middleware chain position |
| `mcp.gateway.middleware` | string | `dlp_scan` | Middleware name |
| `mcp.session_id` | string | `sess-abc123` | Cross-request correlation |
| `mcp.decision_id` | string | `dec-xyz789` | Per-request decision ID |
| `mcp.trace_id` | string | `trace-def456` | Distributed trace ID |
| `mcp.spiffe_id` | string | `spiffe://poc.local/...` | Agent identity |
| `mcp.tool` | string | `tavily_search` | Tool being invoked |
| `mcp.result` | string | `allowed`, `denied`, `flagged` | Middleware decision |
| `mcp.reason` | string | `hash_mismatch` | Reason for decision |

These attributes are the contract between the gateway and any OTel backend. Changing them is a breaking change.

---

### 4.4 Error Response Design

#### 4.4.1 The Problem

Phase 1 error responses are inconsistent across middleware layers:

| Middleware | Current Format | HTTP Code |
|-----------|---------------|-----------|
| DLP | `"Forbidden: Request contains sensitive credentials"` (plain text via `http.Error`) | 403 |
| OPA | `"Policy denied: tool_not_authorized"` (plain text via `http.Error`) | 403 |
| Step-Up Gating | `{"error":"step_up_gating_denied","reason":"...","gate":"...","risk_score":N,"risk_breakdown":{...}}` (JSON) | 403 |
| Tool Registry | `"Tool not authorized: hash_mismatch"` (plain text via `http.Error`) | 403 |
| SPIFFE Auth | `"Missing X-SPIFFE-ID header"` (plain text) | 401 |
| Rate Limit | (no body, just headers) | 429 |
| Request Size | (standard Go `http.MaxBytesError`) | 413 |
| Circuit Breaker | (standard 503) | 503 |
| UI Capability | `{"error":"ui_capability_denied","detail":"..."}` (JSON) | 403 |

An agent developer handling these errors must implement at least three parsing paths: plain text, JSON with `error`/`reason`, and JSON with `error`/`detail`. This is poor DX.

#### 4.4.2 Unified Error Response Format

Phase 2 standardizes ALL gateway error responses to a single JSON envelope:

```json
{
  "error": {
    "code": "dlp_credentials_detected",
    "message": "Request blocked: payload contains sensitive credentials (AWS access key pattern detected)",
    "middleware": "dlp_scan",
    "middleware_step": 7,
    "decision_id": "dec-a1b2c3d4",
    "trace_id": "trace-e5f6g7h8",
    "details": {
      "flags": ["blocked_content"],
      "pattern_type": "aws_access_key"
    },
    "remediation": "Remove or redact credentials from the request payload. Use $SPIKE{ref:path/to/secret} token references instead of raw credentials.",
    "docs_url": "https://github.com/example/agentic-ref-arch/blob/main/docs/errors/dlp-credentials.md"
  }
}
```

**Envelope fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `error.code` | Yes | Machine-readable error code (stable, for programmatic handling) |
| `error.message` | Yes | Human-readable description (may change between versions) |
| `error.middleware` | Yes | Which middleware produced the error |
| `error.middleware_step` | Yes | Position in the 13-step chain (1-13) |
| `error.decision_id` | Yes | Correlates with audit log for investigation |
| `error.trace_id` | Yes | Correlates with OTel trace |
| `error.details` | No | Middleware-specific structured data |
| `error.remediation` | No | Suggested fix for the developer |
| `error.docs_url` | No | Link to detailed error documentation |

#### 4.4.3 Error Code Catalog

| Code | HTTP | Middleware | Meaning |
|------|------|-----------|---------|
| `auth_missing_identity` | 401 | spiffe_auth | No X-SPIFFE-ID header or SVID |
| `auth_invalid_identity` | 401 | spiffe_auth | SPIFFE ID format invalid |
| `authz_policy_denied` | 403 | opa_policy | OPA policy denied the request |
| `authz_no_matching_grant` | 403 | opa_policy | No grant exists for this SPIFFE ID + tool |
| `authz_tool_not_found` | 403 | opa_policy | Tool not found in any grant |
| `registry_hash_mismatch` | 403 | tool_registry | Tool description hash does not match registry |
| `registry_tool_unknown` | 403 | tool_registry | Tool not in registry |
| `dlp_credentials_detected` | 403 | dlp_scan | Request contains credentials (fail-closed) |
| `dlp_pii_detected` | 200* | dlp_scan | Request contains PII (audit-only, not blocked) |
| `stepup_denied` | 403 | step_up_gating | Risk score exceeds threshold |
| `stepup_approval_required` | 403 | step_up_gating | Human approval needed |
| `stepup_guard_blocked` | 403 | step_up_gating | Guard model detected injection/jailbreak |
| `stepup_destination_blocked` | 403 | step_up_gating | Destination not on allowlist |
| `deepscan_blocked` | 403 | deep_scan | Guard model flagged content |
| `ratelimit_exceeded` | 429 | rate_limit | Per-agent rate limit exceeded |
| `circuit_open` | 503 | circuit_breaker | Upstream is unhealthy |
| `request_too_large` | 413 | request_size | Payload exceeds size limit |
| `ui_capability_denied` | 403 | ui_capability | UI capability not granted |
| `ui_resource_blocked` | 403 | ui_resource | UI resource failed content controls |

*`dlp_pii_detected` is not an error response (request continues); it appears as a flag in the audit log and as a span attribute.

#### 4.4.4 Error Experience by Persona

**Marcus (Agent Developer):**
```python
# SDK handles error parsing uniformly
result = gateway.call_tool("bash", {"command": "ls"})
if result.denied:
    print(f"Blocked by {result.error.middleware} (step {result.error.middleware_step})")
    print(f"Reason: {result.error.message}")
    print(f"Fix: {result.error.remediation}")
    # Output:
    # Blocked by opa_policy (step 6)
    # Reason: Tool 'bash' requires step-up approval (critical risk level)
    # Fix: Provide X-Step-Up-Token header or use a lower-risk tool alternative.
```

**Ops (Investigating a denial):**
The error includes `decision_id` and `trace_id`. The operator takes the `trace_id` to Phoenix and sees the full 13-span waterfall. The `decision_id` maps to a specific audit log entry with the full hash chain context.

---

### 4.5 Agent Integration SDK Design

#### 4.5.1 Design Goal

Reduce the ~120 lines of duplicated `GatewayClient` code (currently copy-pasted between `agents/dspy_researcher/agent.py` and `agents/pydantic_researcher/agent.py`) to a shared library with a clean, framework-independent interface.

#### 4.5.2 Python SDK Interface

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

# Minimal setup (3 lines)
client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/my-agent/dev",
)

# Call a tool (1 line)
result = client.call("tavily_search", query="SPIFFE vs OAuth", max_results=5)

# Handle denial (structured)
try:
    result = client.call("bash", command="rm -rf /")
except GatewayError as e:
    print(e.code)          # "authz_policy_denied"
    print(e.middleware)    # "opa_policy"
    print(e.step)          # 6
    print(e.remediation)   # "Tool 'bash' is denied by policy..."
    print(e.trace_id)      # "trace-abc123" (for ops investigation)
```

#### 4.5.3 SDK Responsibilities

The SDK handles:
1. MCP JSON-RPC envelope construction (jsonrpc, method, params, id)
2. Required headers (X-SPIFFE-ID, X-Session-ID, Content-Type)
3. Unified error parsing (all error formats parsed into `GatewayError`)
4. Retry logic for transient failures (503 with exponential backoff)
5. OpenTelemetry span creation (optional, enabled by passing a tracer)
6. Session ID management (auto-generated if not provided)

The SDK does NOT handle:
- Framework-specific tool registration (that is the framework's job)
- Authentication against real SPIRE (that requires mTLS, not the SDK's concern)
- Response transformation (the SDK returns raw MCP JSON-RPC results)

#### 4.5.4 Framework Integration Examples

**PydanticAI (Phase 2 target -- 8 lines of integration code):**
```python
from mcp_gateway_sdk import GatewayClient
from pydantic_ai import Agent, RunContext

client = GatewayClient(url="http://localhost:9090", spiffe_id="spiffe://...")
agent = Agent("groq:llama-3.3-70b-versatile", deps_type=GatewayClient)

@agent.tool
def search(ctx: RunContext[GatewayClient], query: str) -> str:
    return ctx.deps.call("tavily_search", query=query)
```

**DSPy (Phase 2 target -- 10 lines of integration code):**
```python
from mcp_gateway_sdk import GatewayClient
import dspy

client = GatewayClient(url="http://localhost:9090", spiffe_id="spiffe://...")

class SecureSearch(dspy.Module):
    def __init__(self, gw: GatewayClient):
        super().__init__()
        self.gw = gw
    def forward(self, query: str):
        return self.gw.call("tavily_search", query=query)
```

**Raw HTTP (always works -- `curl`):**
```bash
curl -s -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/my-agent/dev" \
  -H "X-Session-ID: $(uuidgen)" \
  -d '{"jsonrpc":"2.0","method":"read","params":{"file_path":"go.mod"},"id":1}'
```

#### 4.5.5 Go SDK Interface

For Go-based agents or tools:

```go
import "github.com/example/agentic-security-poc/sdk/gateway"

client := gateway.NewClient(
    gateway.WithURL("http://localhost:9090"),
    gateway.WithSPIFFEID("spiffe://poc.local/agents/my-agent/dev"),
)

result, err := client.Call(ctx, "tavily_search", map[string]any{
    "query": "SPIFFE authentication",
})
if err != nil {
    var gwErr *gateway.Error
    if errors.As(err, &gwErr) {
        fmt.Printf("Blocked by %s (step %d): %s\n",
            gwErr.Middleware, gwErr.Step, gwErr.Message)
    }
}
```

---

### 4.6 Deep Scan Configuration UX

#### 4.6.1 Setup-Time Configuration

Deep scan behavior is configured at setup time through the CLI (see Section 4.1.2). The three key decisions are:

1. **API key**: Is GROQ_API_KEY available? If not, deep scan is disabled entirely.
2. **Fallback policy**: When the guard model is unavailable at runtime, fail-closed or fail-open?
3. **Timeout**: How long to wait for the guard model before applying the fallback policy.

These choices are stored in `.env` and can be changed by editing the file and restarting.

#### 4.6.2 Runtime Behavior Communication

When deep scan blocks a request, the error response follows the unified format:

```json
{
  "error": {
    "code": "deepscan_blocked",
    "message": "Request blocked: guard model detected potential prompt injection (probability 0.87, threshold 0.30)",
    "middleware": "deep_scan",
    "middleware_step": 10,
    "decision_id": "dec-xyz789",
    "trace_id": "trace-abc123",
    "details": {
      "injection_probability": 0.87,
      "jailbreak_probability": 0.12,
      "threshold": 0.30,
      "model": "meta-llama/llama-prompt-guard-2-86m"
    },
    "remediation": "Review the request payload for prompt injection patterns. If this is a false positive, contact the gateway administrator to adjust the guard threshold."
  }
}
```

When the guard model is unavailable and the fallback policy is fail-closed:

```json
{
  "error": {
    "code": "deepscan_unavailable_fail_closed",
    "message": "Request blocked: guard model unavailable and fallback policy is fail-closed",
    "middleware": "deep_scan",
    "middleware_step": 10,
    "decision_id": "dec-xyz789",
    "trace_id": "trace-abc123",
    "details": {
      "guard_error": "groq API returned status 429: rate limited",
      "fallback_policy": "fail_closed"
    },
    "remediation": "The guard model is temporarily unavailable. If this is a Groq rate limit issue, wait and retry. To change fallback policy, edit DEEP_SCAN_FALLBACK in .env (requires restart)."
  }
}
```

---

## 5. System Boundaries and Changeability

### 5.1 Interface Contracts

The following interfaces are the system boundaries that enable independent changeability. Changing the implementation behind these boundaries should not require changes to consumers.

| Boundary | Contract | Consumers | Changeability Concern |
|----------|----------|-----------|----------------------|
| Error response format | JSON envelope (Section 4.4.2) | Agent SDKs, dashboards, compliance report | Adding new error codes is non-breaking. Changing envelope structure is breaking. |
| OTel span attributes | Attribute schema (Section 4.3.3) | Phoenix, any OTel backend, dashboards | Adding attributes is non-breaking. Removing or renaming is breaking. |
| Compliance report schema | CSV columns (Section 4.2.2) | Vanta, Drata, auditors, custom tools | Adding columns is non-breaking. Removing or renaming is breaking. |
| SDK API | `GatewayClient.call()` signature | Agent developers | Adding optional params is non-breaking. Changing required params is breaking. |
| CLI setup | Question flow, `.env` output | Setup scripts, CI/CD | Adding questions is non-breaking. Changing `.env` key names is breaking. |
| Audit log format | AuditEvent JSON schema | Compliance report, SIEM ingestion | Adding fields is non-breaking. Removing or renaming is breaking. |

### 5.2 Module Boundaries

These are the key abstractions that enable independent development, testing, and replacement.

```
+------------------------------------------------------------------+
|                         CLI Setup                                |
|  (wizard flow, prerequisite checks, .env generation)             |
+------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +------------------+  +------------------+
| Gateway Core     |  | Compliance       |  | SDK              |
| (13 middleware)  |  | Report Generator |  | (Python, Go)     |
|                  |  |                  |  |                  |
| Each middleware  |  | Control mapper   |  | Error parser     |
| is independently |  | Evidence         |  | Retry logic      |
| testable via     |  | collector        |  | OTel integration |
| http.Handler     |  | Report renderer  |  |                  |
+------------------+  +------------------+  +------------------+
         |                    |
         v                    v
+------------------+  +------------------+
| Audit Logger     |  | OTel Exporter    |
| (hash-chained    |  | (span creation,  |
|  JSONL)          |  |  export)         |
+------------------+  +------------------+
```

**Key isolation points:**
- Each middleware is an `http.Handler` wrapper. It can be tested in isolation with `httptest`.
- The compliance report generator reads audit logs and configs; it does not import gateway code.
- The SDK is a standalone package with no dependency on gateway internals.
- The CLI setup generates `.env` files; it does not start services directly (that is `docker compose`'s job).

### 5.3 Extension Points for Phase 3

Phase 2 designs should leave these doors open:

| Phase 3 Concern | Phase 2 Design Decision |
|-----------------|------------------------|
| Streaming MCP | Error format works for both request/response and streaming. Span structure allows for long-lived spans. |
| Plugin ecosystem | Tool registry is already a YAML config. Phase 2 adds hot-reload with attestation, which is the foundation for dynamic plugin registration. |
| New compliance frameworks | Compliance report uses a control taxonomy (Section 4.2.4) that can be extended with new framework mappings without changing the report generator core. |
| Additional OTel backends | Span attributes are vendor-neutral. Swapping Phoenix for Jaeger or Datadog requires only OTel collector config changes. |

---

## 6. Documentation Architecture

### 6.1 Audience-Oriented Structure

Documentation is organized by audience, not by component. A developer looking for "how to connect my agent" should not have to read the compliance section.

```
docs/
  README.md                          # Landing page: what is this, who is it for, quickstart links

  getting-started/
    quickstart.md                    # Ava: git clone to running in 10 commands
    prerequisites.md                 # Ava: required + optional tools with install links
    configuration-reference.md       # Ava/Ops: every .env variable with defaults and consequences

  agent-integration/
    overview.md                      # Marcus: architecture diagram, how agents connect
    python-sdk.md                    # Marcus: pip install, 3-line setup, full API reference
    go-sdk.md                        # Marcus: go get, setup, API reference
    curl-examples.md                 # Marcus: raw HTTP for any language
    error-handling.md                # Marcus: complete error code catalog with examples
    migration-from-phase1.md         # Marcus: migrating existing agents from copy-paste to SDK

  compliance/
    overview.md                      # Eliana: what frameworks are covered, scope boundaries
    running-the-report.md            # Eliana: one command, what to expect
    control-mapping.md               # Eliana: full control-to-framework mapping table
    evidence-guide.md                # Eliana: how to read the evidence, what each field means
    limitations.md                   # Eliana: what is NOT covered (infra hardening, etc.)

  operations/
    observability.md                 # Ops: trace structure, dashboard views, alert setup
    health-monitoring.md             # Ops: health endpoints, circuit breaker, rate limits
    security-tuning.md               # Ops: adjusting risk thresholds, DLP patterns, OPA policies
    session-management.md            # Ops: KeyDB session data, retention, GDPR deletion

  architecture/
    middleware-chain.md              # All: the 13-step chain explained
    threat-model.md                  # All: what threats are addressed and how
    secrets-management.md            # All: SPIKE Nexus, late-binding secrets
    deployment-patterns.md           # All: Docker Compose vs K8s, what differs

  errors/
    dlp-credentials.md               # Per-error-code detailed page
    authz-policy-denied.md           # (linked from error.docs_url in responses)
    stepup-denied.md
    ...
```

### 6.2 Documentation Principles

1. **No dead links.** Every `docs_url` in an error response must resolve to a real page.
2. **No assumptions.** The getting-started guide assumes the reader has Docker and a terminal, nothing else.
3. **Examples over explanations.** Every concept is accompanied by a concrete, copy-pasteable example.
4. **Honest limitations.** Every capability page includes a "Limitations" section describing what is not covered.
5. **Version-stamped.** Documentation references the specific version of the architecture and POC.

---

## 7. Usability Findings (Phase 1 Retrospective)

These findings come from analyzing the Phase 1 codebase, E2E tests, and agent implementations.

### 7.1 Finding: Agent Boilerplate Is Excessive

**Observation:** Both the DSPy and PydanticAI agents implement identical `GatewayClient`, `GatewayDenial`, and `ToolCallResult` classes. The `GatewayClient._do_call()` method is 60+ lines of identical code in both files. The retry logic adds another 30+ lines.

**Impact:** Every new agent framework integration will copy-paste the same 120 lines, introducing maintenance burden and consistency risk.

**Design response:** SDK (Section 4.5).

### 7.2 Finding: Error Parsing Requires Multiple Code Paths

**Observation:** The `_extract_denial_reason()` method in both agents tries JSON first, falls back to plain text, and handles at least three different JSON shapes (`{"error":"..."}`, `{"reason":"..."}`, `{"error":"...","detail":"..."}`).

**Impact:** Agent developers write brittle error handling code that breaks when a new middleware uses a different format.

**Design response:** Unified error response format (Section 4.4).

### 7.3 Finding: Empty Observability Erodes Confidence

**Observation:** Phoenix is running but has zero traces. The OTEL Collector is configured but receives no data from the gateway. An evaluator opening the Phoenix UI sees nothing.

**Impact:** Evaluators cannot verify that security controls are operating. "Trust me, it works" is not evidence.

**Design response:** Mandatory OTel spans per middleware (Section 4.3).

### 7.4 Finding: Security Posture Is Invisible at Setup Time

**Observation:** The current setup (`make up`) starts all services without informing the user what security controls are active. Deep scan is silently disabled without GROQ_API_KEY. Session context is in-memory only (no cross-request detection). The user has no way to know this without reading source code.

**Impact:** Users believe they have a complete security stack when they actually have a partial one.

**Design response:** Security posture summary (Section 4.1.3) and no-silent-degradation principle (Section P1).

### 7.5 Finding: Compliance Evidence Requires Manual Assembly

**Observation:** Phase 1 produces audit logs, test results, and policy configs, but there is no automated way to assemble these into a compliance package. An evaluator would need to manually map audit events to SOC 2 controls.

**Impact:** Regulated industry evaluators cannot self-serve. They need someone to explain the audit log format, find the relevant entries, and map them to their framework.

**Design response:** One-button compliance report (Section 4.2).

### 7.6 Finding: curl Is Still the Best Integration Test

**Observation:** The E2E tests in `tests/e2e/` use `curl` extensively and parse responses with `jq` and `grep`. Despite the existence of two Python agents, the most reliable way to test the gateway is raw HTTP.

**Impact:** This validates the Framework Independence principle (P5). The SDK is a convenience layer; `curl` must always work.

**Design response:** `curl` examples in docs, raw HTTP always documented alongside SDK (Section 4.5.4).

---

## 8. Decisions and Rationale

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| Unified JSON error envelope | Consistent DX, single parsing path for all middleware | Per-middleware formats (rejected: too many code paths for consumers) |
| Error codes are machine-readable, messages are human-readable | Programmatic handling should not depend on message text | Single string (rejected: cannot be reliably parsed) |
| SDK is framework-independent | PydanticAI, DSPy, LangGraph, CrewAI all use different tool patterns | Framework-specific SDKs (rejected: maintenance burden, scope creep) |
| Compliance report is standalone files (XLSX/CSV/PDF) | Maximum portability, no vendor dependency | Vanta API format (rejected: vendor lock-in), HTML dashboard (rejected: less portable) |
| OTel spans per middleware, not per request | Enables latency analysis per layer, identifies bottlenecks | Single span per request (rejected: insufficient granularity) |
| CLI setup generates .env, does not start services | Separation of concerns; .env is the config artifact, docker compose is the runtime | All-in-one script (rejected: harder to debug, less transparent) |
| Documentation by audience, not by component | Users find what they need without reading irrelevant sections | Component-based docs (rejected: evaluators should not have to read SDK docs) |

---

*This document is the single source of truth for Phase 2 user experience design. It will be validated by the Architect (ARCHITECTURE.md) for technical feasibility and by the BA (BUSINESS.md) for business alignment. Changes require BLT consensus.*
