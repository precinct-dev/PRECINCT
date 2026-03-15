# PRECINCT Gateway -- API Reference

This document is the authoritative reference for the PRECINCT Gateway's HTTP API surface.
The gateway implements the Model Context Protocol (MCP) over HTTP with JSON-RPC 2.0,
passing all tool calls through a 13-layer security middleware chain before forwarding
to the upstream MCP server.

**Version:** 2.4.0
**Base URL:** `http://localhost:9090` (dev mode) or `https://localhost:9443` (SPIFFE mTLS mode)

---

## Table of Contents

1. [Endpoints](#endpoints)
   - [POST / -- Main JSON-RPC Endpoint](#post----main-json-rpc-endpoint)
   - [POST /data/dereference -- Response Firewall Handle Dereference](#post-datadereference----response-firewall-handle-dereference)
   - [GET /health -- Health Check](#get-health----health-check)
   - [POST /openai/v1/chat/completions -- Mediated Model Egress](#post-openaiv1chatcompletions----mediated-model-egress)
   - [Port Adapter Endpoints](#port-adapter-endpoints)
2. [Required Headers](#required-headers)
   - [Response Headers](#response-headers)
3. [SPIFFE ID Schema](#spiffe-id-schema)
4. [JSON-RPC 2.0 Wire Format](#json-rpc-20-wire-format)
5. [Error Response Envelope](#error-response-envelope)
6. [Error Code Catalog](#error-code-catalog)
7. [Middleware Chain](#middleware-chain)
8. [Rate Limiting](#rate-limiting)
9. [Circuit Breaker](#circuit-breaker)
10. [SPIKE Token Format](#spike-token-format)
11. [Available Tools](#available-tools)
12. [curl Examples](#curl-examples)
13. [Canonical v2.4 Contract Artifacts](#canonical-v24-contract-artifacts)
14. [Immutable Audit Evidence Path (K8s)](#immutable-audit-evidence-path-k8s)

---

## Endpoints

### POST / -- Main JSON-RPC Endpoint

The primary endpoint for all MCP tool calls. Every request passes through the full
13-layer security middleware chain (size limit, body capture, SPIFFE auth, audit,
tool registry, OPA policy, DLP, session context, step-up gating, deep scan,
rate limiting, circuit breaker, token substitution) before being forwarded to the
upstream MCP server.

**Request:**

```http
POST / HTTP/1.1
Host: localhost:9090
Content-Type: application/json
X-SPIFFE-ID: spiffe://poc.local/agents/example/dev
X-Session-ID: 550e8400-e29b-41d4-a716-446655440000

{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tavily_search",
    "arguments": {
      "query": "AI security best practices",
      "max_results": 5
    }
  },
  "id": 1
}
```

**Success Response (200 OK):**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Search results..."
      }
    ]
  },
  "id": 1
}
```

**Error Response (4xx/5xx):**

When any middleware rejects the request, the gateway returns a unified error envelope
(see [Error Response Envelope](#error-response-envelope) for full field descriptions):

```json
{
  "code": "authz_policy_denied",
  "message": "OPA policy denied tool access",
  "middleware": "opa_policy",
  "middleware_step": 6,
  "decision_id": "550e8400-e29b-41d4-a716-446655440000",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "details": {
    "risk_level": "high"
  },
  "remediation": "Request elevated privileges or contact admin"
}
```

---

### POST /data/dereference -- Response Firewall Handle Dereference

Used to dereference data handles created by the response firewall. When the response
firewall intercepts upstream responses, it may replace sensitive data with opaque
handles. This endpoint allows authorized callers to retrieve approved views of that
data.

This endpoint is protected by SPIFFE authentication (the caller's SPIFFE ID must
match the original requester who triggered the data handle creation).

**Request:**

```http
POST /data/dereference HTTP/1.1
Host: localhost:9090
Content-Type: application/json
X-SPIFFE-ID: spiffe://poc.local/agents/example/dev

{
  "handle_ref": "a1b2c3d4e5f6"
}
```

**Success Response (200 OK):**

```json
{
  "view_type": "approved_view",
  "tool": "tavily_search",
  "created_at": "2026-01-15T10:30:00Z",
  "data": { "...original response data..." }
}
```

**Error Responses:**

| Status | Condition | Body |
|--------|-----------|------|
| 400 Bad Request | Missing or invalid `handle_ref` | `"Missing handle_ref"` |
| 403 Forbidden | SPIFFE ID mismatch (caller is not the original requester) | `{"error": "spiffe_id_mismatch", "detail": "You are not authorized to dereference this handle."}` |
| 405 Method Not Allowed | Non-POST method | `"Method not allowed"` |
| 410 Gone | Handle expired or not found | `{"error": "handle_expired_or_not_found", "detail": "The data handle has expired or does not exist."}` |

**Notes:**
- Handles expire after `HANDLE_TTL` seconds (default: 300 seconds / 5 minutes).
- Only the agent that triggered the original request can dereference its handles.

---

### GET /health -- Health Check

Returns the gateway's health status, including circuit breaker state. This endpoint
does NOT pass through the security middleware chain.

**Request:**

```http
GET /health HTTP/1.1
Host: localhost:9090
```

**Response (200 OK):**

```json
{
  "status": "ok",
  "circuit_breaker": {
    "state": "closed"
  }
}
```

**Circuit breaker states:**
- `closed` -- Normal operation. All requests pass through.
- `open` -- Too many consecutive failures. Requests are rejected with `circuit_open` (503).
- `half-open` -- Testing recovery. Limited requests allowed through.

---

### POST /openai/v1/chat/completions -- Mediated Model Egress

OpenAI-compatible entrypoint for model egress through PRECINCT policy enforcement.
This route is gateway-mediated only: provider selection, destination controls,
reason-coded denials, and optional synthetic safe fallbacks are all decided by the
gateway before any upstream model call is made.

Mission-bound mediation is available on this route for narrow-purpose agents. It
lets builders declare the agent mission and out-of-scope behavior without relying
on prompts alone.

**Optional mission-bound headers:**

| Header | Description |
|--------|-------------|
| `X-Agent-Purpose` | Declared mission label for the agent, used for audit/projection |
| `X-Mission-Boundary-Mode` | Enables mission-bound enforcement for the request |
| `X-Mission-Allowed-Intents` | Comma-separated allowlist of in-scope intents |
| `X-Mission-Allowed-Topics` | Comma-separated allowlist of in-scope topics |
| `X-Mission-Blocked-Topics` | Comma-separated deny-first topics |
| `X-Mission-Out-Of-Scope-Action` | `deny`, `rewrite`, or `handoff` |
| `X-Mission-Out-Of-Scope-Message` | Safe fallback assistant text when rewrite/handoff is used |

**Behavior notes:**

- If mission-bound metadata is absent, existing model-egress behavior is preserved.
- If the request is out of scope and `X-Mission-Out-Of-Scope-Action=deny`, the
  gateway returns a normal denial.
- If the request is out of scope and the action is `rewrite` or `handoff`, the
  gateway returns a synthetic assistant response and does not call the upstream
  provider.

**Representative model-plane reason codes:**

| Reason code | Meaning |
|-------------|---------|
| `MODEL_ALLOW` | Model request admitted and mediated normally |
| `MODEL_MISSION_SCOPE_DENIED` | Mission-bound policy rejected an out-of-scope request |
| `MODEL_MISSION_SCOPE_SAFE_FALLBACK_APPLIED` | Gateway returned a synthetic safe fallback instead of calling the provider |
| `PROMPT_SAFETY_RAW_REGULATED_CONTENT_DENIED` | Prompt-safety policy rejected the request before provider egress |

---

### DLP RuleOps Admin Endpoints

The DLP RuleOps lifecycle is exposed via admin endpoints:

- `GET /admin/dlp/rulesets`
- `GET /admin/dlp/rulesets/active`
- `POST /admin/dlp/rulesets/create`
- `POST /admin/dlp/rulesets/validate`
- `POST /admin/dlp/rulesets/approve`
- `POST /admin/dlp/rulesets/sign`
- `POST /admin/dlp/rulesets/promote` (`mode=canary|active`)
- `POST /admin/dlp/rulesets/rollback`

Contract details and lifecycle semantics are defined in
`../contracts/v2.4/ruleops-lifecycle.v2.4.md`.

---

### Port Adapter Endpoints

Port adapters translate external protocol requests into `PlaneRequestV2` structs and
run them through the full middleware chain.

#### Discord Adapter Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/discord/send` | Send Discord message (DLP-scanned, SPIKE token redeemed) |
| POST | `/discord/webhooks` | Receive Discord webhook (Ed25519 verified) |
| POST | `/discord/commands` | Execute Discord bot command (tool plane evaluation) |

#### Email Adapter Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/email/send` | Send email (DLP-scanned subject+body, mass-send detection) |
| POST | `/email/webhooks` | Receive email webhook |
| GET/POST | `/email/list` | List email metadata |
| POST | `/email/read` | Read email content (auto-classified) |

---

### Approval Capability Admin Endpoints

High-risk tool/model operations can use short-lived bounded approval capabilities:

- `POST /admin/approvals/request`
- `POST /admin/approvals/grant`
- `POST /admin/approvals/deny`
- `POST /admin/approvals/consume`

Capability tokens are signed, actor/session/action scoped, TTL-bounded, and
single-consume.

---

### Enforcement Profile Admin Endpoints

Runtime enforcement profile metadata is exposed as machine-readable JSON:

- `GET /admin/profiles/status`
- `GET /admin/profiles/export`

Response includes:
- active profile name (`dev`, `prod_standard`, `prod_regulated_hipaa`)
- runtime control toggles (mediation and HIPAA prompt safety gates)
- startup conformance status and any violations

---

### Conformance Harness Invocation

Use the fixture-driven conformance harness to generate a machine-readable report
across contracts, connectors, RuleOps, and profile suites:

- Embedded mode (CI-safe): `go run ./tests/conformance/cmd/harness --output ./build/conformance/conformance-report.json`
- Live mode (local stack): `go run ./tests/conformance/cmd/harness --live --gateway-url http://localhost:9090 --output ./build/conformance/conformance-report.live.json`
- CI/automation target: `make conformance`

The report schema is versioned (`conformance.report.v1`) and defined at:
`../tests/conformance/report.schema.v1.json`.

---

## Canonical v2.4 Contract Artifacts

The frozen v2.4 control-plane contract set and reason-code catalog live in:

- `../contracts/v2.4/contract-set.v2.4.md`
- `../contracts/v2.4/manifest.v2.4.json`
- `../contracts/v2.4/schemas/plane_request_v2.schema.json`
- `../contracts/v2.4/schemas/plane_decision_v2.schema.json`
- `../contracts/v2.4/schemas/connector_manifest_v1.schema.json`
- `../contracts/v2.4/connector-conformance-authority.v2.4.md`
- `../contracts/v2.4/ruleops-lifecycle.v2.4.md`
- `../contracts/v2.4/reason-code-catalog.v2.4.json`
- `../contracts/v2.4/reason-code-catalog.v2.4.md`
- `../contracts/v2.4/CHANGELOG.md`

Compatibility notes:

- Canonical ingress path is `/v1/ingress/submit`; `/v1/ingress/admit` is retained as a compatibility alias during migration.
- `/v1/ingress/submit` and `/v1/ingress/admit` share the same runtime enforcement:
  source-principal checks (`INGRESS_SOURCE_UNAUTHENTICATED`), replay detection
  (`INGRESS_REPLAY_DETECTED` via `event_id`/`nonce`), and freshness checks
  (`INGRESS_FRESHNESS_STALE` via `event_timestamp`).
- v2.4 governance endpoints (`/v1/*`, `/admin/dlp/rulesets*`, `/admin/approvals*`, `/admin/breakglass*`, `/admin/profiles*`, `/admin/loop/runs*`)
  run through the gateway middleware chain for SPIFFE identity enforcement and
  policy hooks.
- v2.4 request failures use the unified `GatewayError` envelope (`code`,
  `middleware`, `middleware_step`, `decision_id`, `trace_id`) while control-plane
  policy decisions continue to use the canonical `reason_code` decision envelope.
- Control-plane endpoints return `reason_code`; middleware chain denials return `code`.

## Immutable Audit Evidence Path (K8s)

The immutable audit sink path for Kubernetes deployments is defined in:

- `../deploy/terraform/observability/audit/audit-s3-config.yaml`
- `../docs/compliance/immutable-audit-evidence-path.md`

Validation + proof generation:

- `kustomize build ../deploy/terraform/observability`
- `bash ../tests/e2e/validate_immutable_audit_sink.sh`

Machine-readable proof artifact:

- `../tests/e2e/artifacts/immutable-audit-sink-proof.json`

Compose boundary reference:

- `../docs/compliance/immutable-audit-evidence-path.md` (Compose fallback limits + compensating checks)

### Runtime Wiring Matrix (v2.4)

The following endpoint families are wired as first-class gateway runtime entrypoints
before upstream proxy forwarding:

| Endpoint family | Runtime entry | Scope |
|-----------------|---------------|-------|
| `/v1/ingress/submit`, `/v1/ingress/admit`, `/v1/context/admit`, `/v1/model/call`, `/v1/tool/execute`, `/v1/loop/check` | Phase 3 control-plane dispatcher | Ingress, context, model, tool, and loop policy decisions |
| `/openai/v1/chat/completions` | OpenAI-compatible model egress entry | Mediated model egress with provider trust/fallback controls and optional policy-intent prepend (`MODEL_POLICY_INTENT_PREPEND_ENABLED`) |
| `/v1/connectors/*` | Connector conformance authority entry | `register`/`validate`/`approve`/`activate`/`revoke` require an admin-authorized SPIFFE principal; `status`/`report` remain SPIFFE-identity gated |
| `/admin/dlp/rulesets*` | RuleOps admin entry | Governed DLP ruleset lifecycle |
| `/admin/approvals*` | Approval capability admin entry | Human-in-the-loop step-up lifecycle |
| `/admin/breakglass*` | Break-glass admin entry | Dual-authorization emergency override lifecycle |
| `/admin/profiles*` | Enforcement profile admin entry | Runtime profile/status/export introspection |
| `/admin/loop/runs*` | Loop admin entry | Loop run metadata and operational observability |

---

## Required Headers

| Header | Required | Applies To | Description | Example |
|--------|----------|------------|-------------|---------|
| `Content-Type` | Yes | `POST /`, `POST /data/dereference` | Must be `application/json` | `application/json` |
| `X-SPIFFE-ID` | Yes | `POST /`, `POST /data/dereference` | SPIFFE identity of the calling agent | `spiffe://poc.local/agents/example/dev` |
| `X-Session-ID` | Yes | `POST /` | Session UUID for cross-request tracking and exfiltration detection | `550e8400-e29b-41d4-a716-446655440000` |
| `X-Agent-Purpose` | No | `POST /openai/v1/chat/completions` | Declared mission label for mission-bound model mediation | `restaurant_order_support` |
| `X-Mission-Boundary-Mode` | No | `POST /openai/v1/chat/completions` | Enables per-request mission-bound enforcement | `enforce` |
| `X-Mission-Allowed-Intents` | No | `POST /openai/v1/chat/completions` | Comma-separated in-scope intent list | `place_order,order_status` |
| `X-Mission-Allowed-Topics` | No | `POST /openai/v1/chat/completions` | Comma-separated in-scope topic list | `menu,burritos,bowls` |
| `X-Mission-Blocked-Topics` | No | `POST /openai/v1/chat/completions` | Comma-separated deny-first topic list | `coding,python,linked lists` |
| `X-Mission-Out-Of-Scope-Action` | No | `POST /openai/v1/chat/completions` | Out-of-scope behavior | `rewrite` |
| `X-Mission-Out-Of-Scope-Message` | No | `POST /openai/v1/chat/completions` | Safe fallback assistant message | `I can help with orders and menu questions only.` |

**Notes:**
- In `SPIFFE_MODE=dev` (default), `X-SPIFFE-ID` is accepted as a plain header.
- In `SPIFFE_MODE=prod`, the SPIFFE ID is extracted from the mTLS client certificate and the header is ignored.
- The `X-Session-ID` must be a valid UUID. The session context middleware uses it to track data flow across requests for exfiltration detection.

### Response Headers

The gateway injects the following headers into proxied responses:

| Header | Type | Description |
|--------|------|-------------|
| `X-Precinct-Principal-Level` | integer | Authority level (0=system, 5=anonymous) |
| `X-Precinct-Principal-Role` | string | Role name (owner, agent, external_user, etc.) |
| `X-Precinct-Principal-Capabilities` | string (comma-sep) | Authorized capabilities (e.g., "execute,read,write") |
| `X-Precinct-Auth-Method` | string | `mtls_svid` (prod) or `header_declared` (dev) |
| `X-Precinct-Reversibility` | string | reversible, costly_reversible, partially_reversible, irreversible |
| `X-Precinct-Backup-Recommended` | boolean string | `"true"` if Score >= 2 |
| `X-Precinct-Escalation-Score` | float | Session escalation score (0.0+) |

---

## Proxied Request Headers

The gateway injects advisory headers into proxied requests forwarded to the upstream MCP server.
These headers are set by the middleware chain and provide security context to the agent framework.

| Header | Type | Set When | Description |
|--------|------|----------|-------------|
| `X-Precinct-Reversibility` | string | Always (for tool calls) | Reversibility category of the action: `reversible`, `costly_reversible`, `partially_reversible`, or `irreversible` |
| `X-Precinct-Backup-Recommended` | boolean string | `RequiresBackup=true` AND action allowed | Set to `"true"` when the action requires a pre-execution state snapshot (reversibility Score >= 2). Agent frameworks should capture current state before executing. Absent for reversible actions or denied requests. |

---

## SPIFFE ID Schema

The gateway uses SPIFFE (Secure Production Identity Framework for Everyone) identities
to authenticate and authorize callers. SPIFFE IDs follow this format:

```
spiffe://<trust-domain>/<class>/<purpose>/<env>
```

**Components:**

| Component | Description | Examples |
|-----------|-------------|---------|
| `trust-domain` | The SPIFFE trust domain | `poc.local` |
| `class` | Identity class | `agents`, `services` |
| `purpose` | Specific purpose/name | `example`, `dspy-agent`, `mcp-gateway` |
| `env` | Environment | `dev`, `staging`, `prod` |

**Examples:**

| SPIFFE ID | Description |
|-----------|-------------|
| `spiffe://poc.local/agents/example/dev` | Development agent |
| `spiffe://poc.local/agents/dspy-agent/prod` | Production DSPy agent |
| `spiffe://poc.local/services/mcp-gateway/prod` | Gateway service identity |

The OPA policy engine uses the SPIFFE ID to determine which tools each agent is allowed
to call. The trust domain must match `SPIFFE_TRUST_DOMAIN` (default: `poc.local`).

---

## JSON-RPC 2.0 Wire Format

The gateway uses the JSON-RPC 2.0 protocol as defined by MCP. All tool calls are
wrapped in a JSON-RPC request envelope.

### Request Format (Tools)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jsonrpc` | string | Yes | Must be `"2.0"` |
| `method` | string | Yes | For tool invocation, use MCP-spec `tools/call` |
| `params` | object | Yes | For `tools/call`, `{"name":"<tool_name>","arguments":{...}}` |
| `id` | integer | Yes | Request identifier (echoed in response) |

**Example:**

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tavily_search",
    "arguments": {
      "query": "MCP security",
      "max_results": 3
    }
  },
  "id": 1
}
```

**Legacy compatibility (deprecated):** Some deployments may still accept the
non-spec shortcut `method="<tool_name>"` with tool-specific params. Prefer `tools/call`
for portability and future compatibility.

### Response Format

**Success:**

| Field | Type | Description |
|-------|------|-------------|
| `jsonrpc` | string | Always `"2.0"` |
| `result` | object | Tool-specific result data |
| `id` | integer | Matches the request `id` |

**JSON-RPC Error (from upstream MCP server):**

| Field | Type | Description |
|-------|------|-------------|
| `jsonrpc` | string | Always `"2.0"` |
| `error` | object | Contains `code` (integer) and `message` (string) |
| `id` | integer | Matches the request `id` |

**Note:** The gateway internally auto-increments the JSON-RPC `id` field when using
MCP transport mode. JSON-RPC errors from the upstream MCP server are translated into
the gateway's unified error envelope with the `mcp_request_failed` error code.

---

## Error Response Envelope

When any middleware in the chain rejects a request, the gateway returns a unified
error envelope. This structure is consistent across all denial paths, enabling
programmatic error handling by AI agents.

**Envelope Structure:**

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `code` | string | Yes | Machine-readable error code (see [Error Code Catalog](#error-code-catalog)) |
| `message` | string | Yes | Human-readable error description |
| `middleware` | string | Yes | Name of the middleware that rejected the request |
| `middleware_step` | integer | Yes | Step number in the 13-layer chain (1-13), or 0 for non-chain middleware |
| `decision_id` | string | Yes | UUID for audit log cross-reference |
| `trace_id` | string | Yes | OpenTelemetry trace ID for distributed tracing correlation |
| `details` | object | No | Optional structured data with additional context |
| `remediation` | string | No | Guidance on how to resolve the error |
| `docs_url` | string | No | Link to relevant documentation |

**Example:**

```json
{
  "code": "dlp_credentials_detected",
  "message": "Credentials detected in request payload",
  "middleware": "dlp_scan",
  "middleware_step": 7,
  "decision_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "details": {
    "category": "credentials"
  },
  "remediation": "Use SPIKE token references instead of embedding credentials directly."
}
```

---

## Error Code Catalog

Complete catalog of all 25 error codes defined in `internal/gateway/middleware/error_codes.go`.

### By Middleware Step

| Code | Step | HTTP | Middleware | Description | Remediation |
|------|------|------|------------|-------------|-------------|
| `request_too_large` | 1 | 413 | `request_size_limit` | Request payload exceeds `MAX_REQUEST_SIZE_BYTES` (default: 10 MB) | Reduce payload size or increase `MAX_REQUEST_SIZE_BYTES` |
| `auth_missing_identity` | 3 | 401 | `spiffe_auth` | Caller identity missing for active SPIFFE mode (`X-SPIFFE-ID` in `dev`, mTLS cert URI SAN in `prod`) | In `dev`, send `X-SPIFFE-ID`; in `prod`, present a valid client certificate with `spiffe://` URI SAN |
| `auth_invalid_identity` | 3 | 401 | `spiffe_auth` | SPIFFE ID is not within the configured trust domain | Use a SPIFFE ID under the `SPIFFE_TRUST_DOMAIN` (default: `poc.local`) |
| `registry_hash_mismatch` | 5 | 403 | `tool_registry_verify` | Tool definition hash does not match the registered hash (possible tool poisoning) | Re-register the tool with the correct hash, or investigate potential tampering |
| `registry_tool_unknown` | 5 | 403 | `tool_registry_verify` | The requested tool is not registered in the tool registry | Register the tool in `config/tool-registry.yaml` |
| `authz_policy_denied` | 6 | 403 | `opa_policy` | OPA policy explicitly denied access to this tool | Check OPA policy grants for this agent/tool combination |
| `authz_no_matching_grant` | 6 | 403 | `opa_policy` | No OPA grant matches this agent and tool combination | Add a grant in the OPA policy for this SPIFFE ID and tool |
| `authz_tool_not_found` | 6 | 403 | `opa_policy` | The tool was not found in OPA policy data | Add the tool to the OPA data document |
| `principal_level_insufficient` | 6 | 403 | `opa_policy` | Requester's principal level too low for this action | Ensure the caller's SPIFFE ID maps to a principal level with adequate privileges for the requested tool |
| `irreversible_action_denied` | 9 | 403 | `step_up_gating` | Irreversible action denied: non-owner + escalated session | Obtain step-up authorization or human approval before executing irreversible actions |
| `dlp_credentials_detected` | 7 | 403 | `dlp_scan` | Credentials (API keys, passwords, tokens) detected in request payload. **Always blocked** -- this is a security invariant | Use `$SPIKE{ref:...}` token references instead of embedding secrets |
| `dlp_injection_blocked` | 7 | 403 | `dlp_scan` | Prompt injection patterns detected and blocked by DLP policy | Remove injection patterns from the request. Policy configurable via `DLP_INJECTION_POLICY` env var (`block` or `flag`) |
| `dlp_pii_blocked` | 7 | 403 | `dlp_scan` | Personally identifiable information detected and blocked by DLP policy | Remove PII from the request or adjust DLP policy in `risk_thresholds.yaml` |
| `exfiltration_detected` | 8 | 403 | `session_context` | Cross-request data exfiltration pattern detected (data from one tool response used in another tool's request in a suspicious pattern) | Review session data flow; ensure legitimate use of cross-tool data |
| `stepup_denied` | 9 | 403 | `step_up_gating` | Step-up authentication denied (generic denial) | Request elevated privileges or reduce risk level of the operation |
| `stepup_approval_required` | 9 | 403 | `step_up_gating` | The operation requires manual human approval before proceeding | Obtain human-in-the-loop approval for this high-risk operation |
| `stepup_guard_blocked` | 9 | 403 | `step_up_gating` | The guard model (LLM safety classifier) blocked the request content | Modify the request content to pass guard model safety checks |
| `stepup_destination_blocked` | 9 | 403 | `step_up_gating` | The request targets a destination not on the allowlist | Add the destination to `config/destinations.yaml` |
| `deepscan_blocked` | 10 | 403 | `deep_scan_dispatch` | The guard model (deep content scan) blocked the request after async analysis | Modify the request content to pass deep scan safety checks |
| `deepscan_unavailable_fail_closed` | 10 | 503 | `deep_scan_dispatch` | The guard model is unavailable and the gateway is configured to fail closed (`DEEP_SCAN_FALLBACK=fail_closed`) | Ensure the guard model API is accessible, or set `DEEP_SCAN_FALLBACK=fail_open` |
| `ratelimit_exceeded` | 11 | 429 | `rate_limit` | Per-agent rate limit exceeded | Wait and retry. Current limits: `RATE_LIMIT_RPM` requests per minute with `RATE_LIMIT_BURST` burst allowance |
| `circuit_open` | 12 | 503 | `circuit_breaker` | Circuit breaker is open due to consecutive upstream failures. Requests are rejected to prevent cascading failures | Wait for the circuit breaker reset timeout (`CIRCUIT_RESET_TIMEOUT`, default: 30s), then retry |

### Non-Chain Middleware (UI Capability Gating)

| Code | Step | HTTP | Middleware | Description | Remediation |
|------|------|------|------------|-------------|-------------|
| `ui_capability_denied` | N/A | 403 | `ui_capability_gating` | UI capabilities not granted for this server/tenant | Add grants in `ui_capability_grants.yaml` |
| `ui_resource_blocked` | N/A | 403 | `ui_resource_controls` | UI resource failed content controls (content-type, size, scan, or hash verification) | Ensure the resource passes all content control checks |

### MCP Transport (Proxy Layer)

| Code | Step | HTTP | Middleware | Description | Remediation |
|------|------|------|------------|-------------|-------------|
| `mcp_transport_failed` | proxy | 502 | `mcp_transport` | Transport-level failure (connection refused, timeout, TLS error) | Ensure the upstream MCP server is running and accessible |
| `mcp_request_failed` | proxy | 502 | `mcp_transport` | The upstream MCP server returned a JSON-RPC error | Check the upstream MCP server logs for the root cause |
| `mcp_invalid_response` | proxy | 502 | `mcp_transport` | The upstream MCP server returned a malformed or oversized response | Verify the MCP server returns valid JSON-RPC 2.0 responses within `MAX_REQUEST_SIZE_BYTES` |

### Data Source and Escalation Errors

| Code | Step | HTTP | Middleware | Description | Remediation |
|------|------|------|------------|-------------|-------------|
| `data_source_hash_mismatch` | 5 | 403 | `tool_registry_verify` | External data source content does not match registered hash | Re-register the data source with the correct content hash, or investigate potential tampering |
| `unregistered_data_source` | 5 | 403 | `tool_registry_verify` | Data source URI not in registry | Register the data source in `config/tool-registry.yaml` |
| `escalation_emergency` | 8 | 403 | `session_context` | Session escalation score exceeds emergency threshold | Review session action history; reduce destructive operations or start a new session |

### Port Adapter Errors

| Code | Step | HTTP | Middleware | Description | Remediation |
|------|------|------|------------|-------------|-------------|
| `discord_signature_invalid` | N/A | 401 | Port | Discord webhook Ed25519 signature verification failed | Verify `DISCORD_PUBLIC_KEY` env var matches the Discord application's public key |

---

## Middleware Chain

Every request to `POST /` passes through these middleware layers in order:

| Step | Middleware | Function | Blocks? |
|------|-----------|----------|---------|
| 1 | Request Size Limit | Rejects payloads exceeding `MAX_REQUEST_SIZE_BYTES` (default: 10 MB) | Yes (413) |
| 2 | Body Capture | Captures request body into context for downstream middleware | No |
| 3 | SPIFFE Auth | Validates caller identity (`X-SPIFFE-ID` in `dev`; mTLS cert URI SAN in `prod`; header ignored in `prod`) | Yes (401) |
| 4 | Audit Log | Creates audit event with decision ID; logs result after request completes | No |
| 5 | Tool Registry Verify | Verifies tool exists in registry and hash matches (anti-poisoning) | Yes (403) |
| 6 | OPA Policy | Evaluates authorization policy (agent + tool + path grants) | Yes (403) |
| 7 | DLP Scanner | Scans for credentials, prompt injection, and PII | Yes (403) |
| 8 | Session Context | Tracks data flow across requests; detects exfiltration patterns | Yes (403) |
| 9 | Step-Up Gating | Risk scoring, destination allowlist check, guard model pre-check | Yes (403) |
| 10 | Deep Scan | Async guard model content analysis (LLM safety classifier) | Yes (403/503) |
| 11 | Rate Limiter | Per-agent token bucket rate limiting | Yes (429) |
| 12 | Circuit Breaker | Protects upstream from cascading failures | Yes (503) |
| 13 | Token Substitution | Replaces `$SPIKE{...}` tokens with actual secrets from SPIKE Nexus | Yes (403) |
| -- | Response Firewall | Intercepts upstream responses; replaces sensitive data with handles | Post-proxy |
| -- | Proxy | Forwards request to upstream MCP server via detected transport | -- |

**Security invariant:** Token substitution (step 13) is the LAST middleware before the proxy.
No other middleware in the chain ever sees actual secret values -- they only see the
`$SPIKE{...}` token references.

---

## Rate Limiting

The gateway enforces per-agent rate limiting using a token bucket algorithm backed
by KeyDB (distributed) or in-memory storage (single instance).

| Parameter | Env Var | Default | Description |
|-----------|---------|---------|-------------|
| Requests per minute | `RATE_LIMIT_RPM` | 600 | Sustained request rate per SPIFFE ID |
| Burst allowance | `RATE_LIMIT_BURST` | 100 | Maximum burst above sustained rate |

**Scope:** Rate limits are applied per SPIFFE ID. Each agent identity has its own
independent token bucket.

**Demo configuration:** For demos, use `RATE_LIMIT_RPM=60` and `RATE_LIMIT_BURST=10`
to make rate limiting observable at human timescales.

**Response on limit exceeded:**

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "code": "ratelimit_exceeded",
  "message": "Rate limit exceeded",
  "middleware": "rate_limit",
  "middleware_step": 11,
  "decision_id": "...",
  "trace_id": "...",
  "remediation": "Reduce request frequency or contact admin to increase limits"
}
```

---

## Circuit Breaker

The circuit breaker protects the upstream MCP server from cascading failures.

| Parameter | Env Var | Default | Description |
|-----------|---------|---------|-------------|
| Failure threshold | `CIRCUIT_FAILURE_THRESHOLD` | 5 | Consecutive failures before opening circuit |
| Reset timeout | `CIRCUIT_RESET_TIMEOUT` | 30 | Seconds in Open state before trying Half-Open |
| Success threshold | `CIRCUIT_SUCCESS_THRESHOLD` | 2 | Consecutive successes in Half-Open before closing |

**State transitions:**
- `closed` -> `open`: After `CIRCUIT_FAILURE_THRESHOLD` consecutive upstream failures.
- `open` -> `half-open`: After `CIRCUIT_RESET_TIMEOUT` seconds.
- `half-open` -> `closed`: After `CIRCUIT_SUCCESS_THRESHOLD` consecutive successes.
- `half-open` -> `open`: On any failure during half-open testing.

---

## SPIKE Token Format

The gateway supports late-binding secret injection via SPIKE (SPIFFE-based secret
management). Agents embed token references in their requests instead of actual
secrets. The gateway substitutes tokens with real values at step 13, immediately
before proxying to the upstream MCP server.

### Token Syntax

```
$SPIKE{ref:<hex>,exp:<seconds>,scope:<scope>}
```

| Component | Required | Format | Description |
|-----------|----------|--------|-------------|
| `ref` | Yes | Hexadecimal | Reference to the secret stored in SPIKE Nexus |
| `exp` | No | Integer | Token expiration in seconds |
| `scope` | No | Dotted string | Required access scope (e.g., `tools.tavily.search`) |

**Examples:**

```
$SPIKE{ref:abc123}
$SPIKE{ref:deadbeef,exp:3600}
$SPIKE{ref:1a2b3c,exp:7200,scope:tools.s3.read}
```

### Usage in Requests

Embed SPIKE tokens anywhere in the JSON request body where a secret value is needed:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "tavily_search",
    "arguments": {
      "query": "AI security",
      "api_key": "$SPIKE{ref:abc123,exp:3600,scope:tools.tavily.search}"
    }
  },
  "id": 1
}
```

The gateway replaces `$SPIKE{ref:abc123,exp:3600,scope:tools.tavily.search}` with
the actual secret value before the request reaches the MCP server.

### Security Invariant

Token substitution is the **innermost** middleware (step 13) -- the last step before
the proxy. This ensures:
- No upstream middleware ever sees actual secret values.
- DLP scanning (step 7) sees only token references, not secrets.
- Audit logs record token references, not secret values.
- If any middleware rejects the request, secrets are never fetched or exposed.

### Scope Validation

When a scope is specified in the token, the gateway validates it against the tool's
`required_scope` defined in `config/tool-registry.yaml`. If the scope does not match,
the request is rejected with a 403 error.

---

## Available Tools

Tools are registered in `config/tool-registry.yaml`. Each tool has a SHA-256 hash
computed over its description and input schema, used for poisoning detection.

| Tool Name | Description | Risk Level | Step-Up Required | Required Scope |
|-----------|-------------|------------|------------------|----------------|
| `tavily_search` | Search the web using Tavily API | medium | No | `tools.tavily.search` |
| `read` | Read file contents from filesystem | low | No | `tools.filesystem.read` |
| `grep` | Search for patterns in files | low | No | `tools.filesystem.read` |
| `bash` | Execute shell commands | critical | **Yes** | `tools.shell.execute` |
| `s3_list_objects` | List objects in an S3 bucket | low | No | `tools.s3.list` |
| `s3_get_object` | Read an object from an S3 bucket | low | No | `tools.s3.read` |

For the CLI-mediated `bash` tool, the gateway permits only an allowlisted payload
command set and rejects nested shell interpreter invocations such as `bash -c`
and `sh -c`, even when a custom CLI capability would otherwise allow those
command names.

**Hash verification:** On each request, the gateway recomputes the tool's hash and
compares it against the registered value. A mismatch triggers `registry_hash_mismatch`
(403), indicating potential tool definition tampering.

**Hot reload:** The tool registry supports hot-reload via filesystem watching. When
`config/tool-registry.yaml` is modified, the registry reloads automatically without
gateway restart.

---

## curl Examples

### 1. Successful Tool Call

```bash
curl -s -X POST http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/example/dev" \
  -H "X-Session-ID: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "tavily_search",
      "arguments": {
        "query": "AI security best practices",
        "max_results": 3
      }
    },
    "id": 1
  }' | jq .
```

### 2. Tool Call Denied by OPA Policy

Request a tool that the agent does not have a grant for:

```bash
curl -s -X POST http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/untrusted/dev" \
  -H "X-Session-ID: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "bash",
      "arguments": {
        "command": "ls -la"
      }
    },
    "id": 1
  }' | jq .
```

Expected response (403):

```json
{
  "code": "authz_policy_denied",
  "message": "OPA policy denied tool access",
  "middleware": "opa_policy",
  "middleware_step": 6,
  "decision_id": "...",
  "trace_id": "..."
}
```

### 3. Rate-Limited Request

Send requests in rapid succession to trigger rate limiting:

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:9090/ \
    -H "Content-Type: application/json" \
    -H "X-SPIFFE-ID: spiffe://poc.local/agents/example/dev" \
    -H "X-Session-ID: 550e8400-e29b-41d4-a716-446655440000" \
    -d '{
      "jsonrpc": "2.0",
      "method": "tools/call",
      "params": {"name":"tavily_search","arguments":{"query":"test"}},
      "id": '"$i"'
    }'
done
```

Once the rate limit is exceeded, responses return 429:

```json
{
  "code": "ratelimit_exceeded",
  "message": "Rate limit exceeded",
  "middleware": "rate_limit",
  "middleware_step": 11,
  "decision_id": "...",
  "trace_id": "..."
}
```

### 4. Health Check

```bash
curl -s http://localhost:9090/health | jq .
```

Expected response (200):

```json
{
  "status": "ok",
  "circuit_breaker": {
    "state": "closed"
  }
}
```

### 5. Data Handle Dereference

After receiving a data handle from the response firewall:

```bash
curl -s -X POST http://localhost:9090/data/dereference \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/example/dev" \
  -d '{
    "handle_ref": "a1b2c3d4e5f6"
  }' | jq .
```

---

## Environment Variables Reference

Key gateway configuration parameters that affect API behavior:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | HTTP listen port |
| `UPSTREAM_URL` | `http://host.docker.internal:8081/mcp` | Upstream MCP server URL |
| `SPIFFE_MODE` | `dev` | `dev` (header-based auth) or `prod` (mTLS) |
| `SPIFFE_TRUST_DOMAIN` | `poc.local` | SPIFFE trust domain for identity validation |
| `SPIFFE_LISTEN_PORT` | `9443` | HTTPS port when `SPIFFE_MODE=prod` |
| `MAX_REQUEST_SIZE_BYTES` | `10485760` (10 MB) | Maximum request body size |
| `RATE_LIMIT_RPM` | `600` | Requests per minute per agent |
| `RATE_LIMIT_BURST` | `100` | Burst allowance above sustained rate |
| `CIRCUIT_FAILURE_THRESHOLD` | `5` | Consecutive failures to open circuit |
| `CIRCUIT_RESET_TIMEOUT` | `30` | Seconds before half-open retry |
| `CIRCUIT_SUCCESS_THRESHOLD` | `2` | Successes to close circuit from half-open |
| `HANDLE_TTL` | `300` | Data handle expiry in seconds |
| `DEEP_SCAN_TIMEOUT` | `5` | Guard model timeout in seconds |
| `DEEP_SCAN_FALLBACK` | `fail_closed` | `fail_closed` (reject) or `fail_open` (allow) when guard model unavailable |
| `DLP_INJECTION_POLICY` | (YAML config) | Override injection DLP policy: `block` or `flag` |
| `GUARD_MODEL_ENDPOINT` | `https://api.groq.com/openai/v1` | Guard model API base URL |
| `GUARD_MODEL_NAME` | `meta-llama/llama-prompt-guard-2-86m` | Guard model identifier |
| `GUARD_API_KEY` | (falls back to `GROQ_API_KEY`) | API key for guard model |
| `SPIKE_NEXUS_URL` | (empty) | SPIKE Nexus URL for secret redemption |
| `MCP_TRANSPORT_MODE` | `mcp` | `mcp` (JSON-RPC transport) or `proxy` (reverse proxy) |
| `MCP_REQUEST_TIMEOUT` | `30` | Per-request timeout in seconds for MCP calls |
| `KEYDB_URL` | (empty) | KeyDB URL for distributed session/rate limit storage |
| `SESSION_TTL` | `3600` | Session expiry in seconds |

---

## Transport Modes and Enforcement Notes

The gateway enforces the same 13-layer inbound security chain in both transport modes. The key difference is how the gateway communicates with the upstream MCP server:

- `MCP_TRANSPORT_MODE=mcp`: the gateway acts as an MCP JSON-RPC client to the upstream MCP server. This enables internal control-plane calls (for example: `tools/list` refreshes used by security enforcement).
- `MCP_TRANSPORT_MODE=proxy`: the gateway reverse-proxies requests to the upstream. In `dev`, upstream-introspection can run in compatibility mode (request may proceed with `hash_verified=false` when no refresher exists). In strict production-intent profiles, observed-hash verification is fail-closed and missing/failed refresh denies `tools/call`.

Security controls to expect in both modes:
- UI controls are enforced (capability mediation / blocking).
- Deep scan can deny requests with `deepscan_blocked` (depending on policy, model availability, and fallback configuration).
- Tool registry verification is gateway-owned: the baseline allowlist lives in `config/tool-registry.yaml`, and the gateway compares it to observed upstream tool metadata from `tools/list` (in `mcp` mode the gateway can refresh observed metadata internally when needed).
