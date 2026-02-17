# RFA-70p: Historical E2E Validation Report (Archived Snapshot)

**Snapshot Date:** 2026-02-06
**Snapshot Branch:** epic/RFA-qq0-poc-docker-compose
**Snapshot Epic:** RFA-qq0 (POC Docker Compose)
**As Of (Current Program Context):** 2026-02-16
**Status:** Archived historical validation output, retained for traceability.

## Scope Notice

This report captures a point-in-time validation run from 2026-02-06 and is not the
authoritative statement of current production-readiness status. Use this as historical
evidence only.

For current status:

- `current-state-and-roadmap.md` (as-built summary + residual risks)
- active closure stories in epic `RFA-l6h6.6`
- latest-source OpenClaw rerun evidence:
  - `POC/tests/e2e/artifacts/rfa-t1hb-run-all-20260216T185105Z.log`
  - `POC/tests/e2e/artifacts/rfa-t1hb-openclaw-campaign-20260216T185105Z.log`
- latest-source final decision + follow-up closure:
  - `POC/docs/security/openclaw-latest-source-final-decision-2026-02-16.md` (`RFA-655e` accepted/closed)

Claim reconciliation (historical -> current):

| Historical statement in this report | Current status (2026-02-16) | Evidence source |
|-------------------------------------|------------------------------|-----------------|
| “SPIKE Nexus commented out in compose” (known gap table) | SPIKE Nexus is active in compose and validated in later stories. | `docker-compose.yml`, accepted SPIKE parity stories |
| “mTLS enforcement dev-mode only” (known gap table) | Strict-profile startup and peer identity pinning are implemented. | accepted `RFA-l6h6.6.6` evidence |
| “Security scanning as future/partial” | CI + security scanning workflow and dependabot config are now present. | accepted `RFA-l6h6.6.7`, `.github/workflows/security-scan.yml`, `.github/dependabot.yml` |

Known residual risks (current, not from 2026-02-06 snapshot):

1. Hosted CI run links are not embedded in this repository snapshot.
2. EKS remains offline-validated unless separately deployed in cloud.
3. OpenClaw latest-source promotion decisions must stay tied to upstream baseline commit `5d40d47501c19465761f503ebb12667b83eea84f` while preserving the separation model (`~/workspace/openclaw` upstream source vs `POC` security wrapper).

## Executive Summary

The Docker Compose stack was validated end-to-end against the Reference Architecture
(v2.2) Section 10.13.1 Local Readiness Checklist and the 5 required demo scenarios.

**Result: 65 PASS / 0 FAIL / 1 SKIP out of 66 total checks across 7 test suites.**

All core security capabilities are operational. The single skip is a known limitation
(cross-request exfiltration detection requires sticky sessions, which HTTP does not
provide by default).

## Stack Health

All 5 services running and healthy:

| Service | Image | Status | Port |
|---------|-------|--------|------|
| spire-server | ghcr.io/spiffe/spire-server:1.10.0 | Up (healthy) | 8080-8081 |
| spire-agent | spire-agent-wrapper:latest | Up (healthy) | - |
| mcp-security-gateway | mcp-security-gateway:latest | Up (healthy) | 9090 |
| otel-collector | otel/opentelemetry-collector-contrib:latest | Up | 4317-4318 |
| phoenix | arizephoenix/phoenix:latest | Up (healthy) | 6006 |

## Scenario Results

### Scenario A: Happy Path (9 PASS / 0 FAIL)
- Authorized tool call (`read`) passes through full 13-middleware chain
- Audit event emitted with all required fields (session_id, decision_id, trace_id, spiffe_id, prev_hash, bundle_digest, registry_digest)
- Security metadata block present with tool_hash_verified
- Phoenix UI reachable, OTEL Collector running
- Sequential tool calls produce sequential audit events
- Tavily search tool call passes through middleware chain

### Scenario B: Security Denial (9 PASS / 0 FAIL)
- `bash` tool denied (tool_not_authorized via OPA -- critical-risk requires step-up)
- Unknown tool (`nonexistent_tool`) denied with `tool_not_found`
- Unregistered SPIFFE ID denied with `no_matching_grant`
- Denial events recorded in audit log
- Structured error responses (no panics)
- Gateway remains healthy after 5 rapid denial requests

### Scenario C: Exfiltration Detection (3 PASS / 0 FAIL / 1 SKIP)
- Session context middleware is active (session_id tracked in audit)
- SessionContextMiddleware wired at step 8 in gateway.go
- DetectsExfiltrationPattern() correctly checks sensitive access + external target
- **SKIP:** Cross-request exfiltration blocking requires sticky sessions (see Variance Report)

### Scenario D: Tool Poisoning (7 PASS / 0 FAIL)
- Valid tool call passes hash verification
- Wrong hash blocked: `Tool not authorized: hash_mismatch` (HTTP 403)
- Multiple tools tested (tavily_search, grep) -- all blocked with wrong hashes
- Denial events recorded in audit log
- OPA poisoning pattern detection loaded (7 regex patterns for description-level attacks)

### Scenario E: DLP Detection (8 PASS / 0 FAIL)
- AWS access key detected and blocked: `Forbidden: Request contains sensitive credentials` (HTTP 403)
- RSA private key detected and blocked (HTTP 403)
- SSN flagged but allowed through (PII = audit-only, not blocked)
- Credit card flagged but allowed through (PII = audit-only, not blocked)
- Prompt injection flagged but allowed through (suspicious = audit-only, not blocked)
- Security metadata block present in audit events for DLP scan
- Clean request not flagged by DLP

### Section 10.13.1 Readiness Checklist (16 PASS / 0 FAIL)

1. **Identity:** SPIRE server healthy, SPIRE agent healthy, entries exist for gateway + dspy-researcher + pydantic-researcher, SPIFFE ID appears in audit log
2. **Policy:** OPA embedded and loaded, decision_id present, unauthorized calls denied with 403
3. **Tool Integrity:** Hash mismatch blocked with `hash_mismatch` message
4. **Secrets:** SPIKE token format accepted, token substitution at step 13 (last before proxy)
5. **Audit:** session_id, trace_id, prev_hash (hash chain integrity), bundle_digest, registry_digest all present

### Full 13-Middleware Chain (13 PASS / 0 FAIL)

| Step | Middleware | Evidence | Status |
|------|-----------|----------|--------|
| 1 | Request Size Limit | Request processed (not 413) | PASS |
| 2 | Body Capture | Downstream middleware reads body (OPA, DLP) | PASS |
| 3 | SPIFFE Auth | spiffe_id in audit event | PASS |
| 4 | Audit Logging | session_id, decision_id, trace_id, prev_hash | PASS |
| 5 | Tool Registry Verify | tool_hash_verified in audit | PASS |
| 6 | OPA Policy | bundle_digest proves OPA loaded and ran | PASS |
| 7 | DLP Scan | security block in audit event | PASS |
| 8 | Session Context | session_id assigned | PASS |
| 9 | Step-Up Gating | Low-risk tool bypasses step-up (fast_path) | PASS |
| 10 | Deep Scan Dispatch | Async dispatch point reached | PASS |
| 11 | Rate Limiting | X-Ratelimit-Limit: 100, X-Ratelimit-Remaining: 20 | PASS |
| 12 | Circuit Breaker | Health: {"circuit_breaker":{"state":"closed"}} | PASS |
| 13 | Token Substitution | Positioned last before proxy in gateway.go | PASS |

## Variance Report: Architecture Intent vs Implementation Reality

### Fully Implemented (No Variance)

| Capability | Architecture Section | Implementation Status |
|-----------|---------------------|------------|
| SPIFFE/mTLS identity | 4.5 | SPIRE server+agent, workload entries, dev attestation |
| OPA policy (embedded) | 6.4 | Embedded Rego engine, bundle digest, tool grants |
| Tool registry hash verification | 6.5 | SHA-256 hash mismatch detection, 403 blocking |
| DLP scanning (credentials) | 7.4 | AWS keys, private keys, passwords blocked (fail-closed) |
| DLP scanning (PII) | 7.4 | SSN, credit card, email flagged (audit-only) |
| Session context tracking | 7.5 | Per-session action history, risk scoring |
| Step-up gating | 7.6 | Risk scoring, fast-path for low-risk, guard model integration |
| Rate limiting | 7.7 | Per-agent token bucket, X-RateLimit headers |
| Circuit breaker | 7.7 | State tracking (closed/open/half-open), health endpoint |
| Response firewall | 7.8 | Handle-ized responses, data dereference endpoint |
| Audit hash chain | 8.1 | prev_hash links events, session_id + trace_id |
| Bundle/registry digests | 8.1 | SHA-256 of OPA bundle and tool registry |
| Poisoning pattern detection | 6.5 | 7 OPA regex patterns for description-level attacks |
| Token substitution | 7.3 | Step 13 (last before proxy), $SPIKE{ref:} format |
| Deep scan dispatch | 7.6 | Async dispatch for critical-risk tools |
| Observability pipeline | 8.2 | OTEL Collector -> Phoenix traces |

### Partially Implemented (Known Gaps)

| Gap | Architecture Intent | Implementation Reality | Severity |
|-----|-------------------|-------------|----------|
| Upstream MCP Server | Docker MCP Gateway at :8081/mcp | Not running (port conflict resolved -- was :8080, now :8081) | Low -- proxy works, upstream not started |
| Tool registry service | Dedicated registry API | Placeholder (golang:1.23 sleep infinity) | Low -- config-file registry works |
| SPIKE Nexus | Token-based secrets gateway | Commented out in compose | Medium -- token substitution middleware exists but has no real backend |
| mTLS enforcement | Runtime mTLS between containers | Dev mode (X-SPIFFE-ID header) | Medium -- SPIRE infra ready, mTLS needs cert exchange |
| Exfiltration cross-request | Detect sensitive-read -> external-send across requests | Requires sticky sessions (new session per request without X-Session-ID) | Low -- detection logic works within a session, session persistence is infrastructure concern |
| Deep scan LLM backend | Groq guard model for deep content analysis | No GROQ_API_KEY configured (async no-op) | Low -- middleware wired, needs API key |
| Agent containers | DSPy/PydanticAI agents in Docker | Not defined in compose (agents run externally) | Low -- gateway is framework-agnostic |

### Not Implemented (Out of Scope)

| Capability | Architecture Section | Reason |
|-----------|---------------------|--------|
| Human-in-the-loop approval | 7.6 | Requires UI integration |
| Production SPIRE node attestation | 4.5 | Dev attestation is sufficient for development |
| Key rotation | 7.3 | Production concern |
| Multi-cluster federation | 4.5 | Single cluster deployment |
| Compliance reporting | 8.3 | Production concern |
| MCP-UI (Apps Extension) security | 7.9 | Architecture v2.2 addition, future epic |

## How to Reproduce

```bash
# 1. Start the stack
make up

# 2. Run the full E2E validation
bash tests/e2e/run_all.sh

# 3. Run individual scenarios
bash tests/e2e/scenario_a_happy_path.sh
bash tests/e2e/scenario_b_security_denial.sh
bash tests/e2e/scenario_c_exfiltration.sh
bash tests/e2e/scenario_d_tool_poisoning.sh
bash tests/e2e/scenario_e_dlp.sh
bash tests/e2e/readiness_checklist.sh
bash tests/e2e/middleware_chain_verify.sh
```
