# PRECINCT (Policy-driven Runtime Enforcement & Cryptographic Identity for Networked Compute and Tools) -- AI Skill

This is a structured knowledge file for AI coding assistants. It encodes
PRECINCT, enabling any AI assistant (Claude,
Copilot, Cursor, Gemini, etc.) to generate correct, security-compliant code
for this architecture.

The file uses progressive disclosure: overview first, details on demand.
Sections are self-contained -- an AI assistant can read only the section
relevant to the user's task.

---

## Section 1: Architecture Overview

The PRECINCT Gateway is an HTTP reverse proxy that interposes a 13-layer
security middleware chain between AI agents and MCP (Model Context Protocol)
servers. Every tool call passes through all 13 layers before reaching the
upstream MCP server.

### Request Flow

```
Agent (Go/Python SDK)
  |
  | POST / (JSON-RPC 2.0)
  | Headers: X-SPIFFE-ID or Authorization: Bearer <jwt>, X-Session-ID, Content-Type
  v
Gateway Middleware Chain (steps 1-13)
  |
  | [1]  Request Size Limit       -- reject >10MB payloads (413)
  | [2]  Body Capture             -- capture body into context for downstream use
  | [3]  SPIFFE Auth              -- validate caller identity (401)
  | [4]  Audit Log                -- create audit event with decision_id
  | [5]  Tool Registry Verify     -- verify tool exists + hash matches (403)
  | [6]  OPA Policy               -- evaluate authorization policy (403)
  | [7]  DLP Scanner              -- scan for credentials/injection/PII (403)
  | [8]  Session Context          -- track cross-request data flow (403)
  | [9]  Step-Up Gating           -- risk scoring + guard model pre-check (403)
  | [10] Deep Scan                -- async guard model content analysis (403/503)
  | [11] Rate Limiter             -- per-agent token bucket (429)
  | [12] Circuit Breaker          -- protect upstream from cascading failures (503)
  | [13] Token Substitution       -- replace $SPIKE{...} with real secrets
  |
  v
Upstream MCP Server
  |
  v
Response Firewall (post-proxy)
  |
  v
Agent receives JSON-RPC result
```

### Security Invariants (NEVER VIOLATE)

1. Token substitution MUST be step 13 (innermost). No other middleware ever
   sees actual secret values -- they only see `$SPIKE{...}` references. This
   means DLP scanning (step 7), audit logs (step 4), and all other middleware
   only process token references, never real secrets.

2. DLP credentials detection (`dlp_credentials_detected`) MUST always block.
   The `credentials` DLP category is hardcoded to `block` and is NOT
   overridable via environment variable. This is a security invariant to
   prevent accidental credential leakage through tool calls.

3. Audit logging (step 4) sees the request BEFORE policy, DLP, and other
   enforcement -- this is by design. The audit log records what was attempted,
   not just what was allowed.

4. Circuit breaker is per-tool, not global. One failing upstream tool does
   not block calls to other healthy tools.

5. Rate limiting is per-SPIFFE-ID via KeyDB (distributed) or in-memory
   (single instance). Each agent identity has its own independent token bucket.

6. SPIFFE trust domain validation is exact-match, not prefix-match. A SPIFFE
   ID under `poc.local` will not match a policy for `poc.local.evil`.

### Deployment Modes

| Mode | SPIFFE_MODE | Auth Mechanism | SPIKE | Use Case |
|------|-------------|----------------|-------|----------|
| Development | `dev` | `X-SPIFFE-ID` header or OAuth bearer JWT | Dev redeemer (deterministic mock secrets) | Local development |
| Production | `prod` | mTLS client certificate or OAuth bearer JWT | SPIKE Nexus (real) | Production deployment |

In `dev` mode, the `X-SPIFFE-ID` header is trusted directly unless the caller
authenticates with `Authorization: Bearer <jwt>`. In `prod` mode, the SPIFFE ID
is extracted from the mTLS client certificate unless bearer auth is used.
Validated bearer tokens are mapped to `spiffe://<trust-domain>/external/<subject>`
and stripped before the upstream MCP server sees the request.

---

## Section 2: Go SDK Reference

**Package:** `github.com/precinct-dev/precinct/sdk/go/mcpgateway`
**Supported Go version:** 1.26.1
**External dependency:** `github.com/google/uuid`

### NewClient

```go
func NewClient(url, spiffeID string, opts ...Option) *GatewayClient
```

| Parameter  | Type       | Description                                           |
|------------|------------|-------------------------------------------------------|
| `url`      | `string`   | Gateway base URL (e.g. `"http://localhost:9090"`)     |
| `spiffeID` | `string`   | SPIFFE identity sent in `X-SPIFFE-ID` header          |
| `opts`     | `...Option`| Zero or more configuration options                    |

Returns `*GatewayClient` with auto-generated UUID session ID.

### Call

```go
func (c *GatewayClient) Call(ctx context.Context, toolName string, params map[string]any) (any, error)
```

| Parameter  | Type              | Description                          |
|------------|-------------------|--------------------------------------|
| `ctx`      | `context.Context` | Context for cancellation/deadlines   |
| `toolName` | `string`          | MCP tool name (e.g. `"tavily_search"`) |
| `params`   | `map[string]any`  | JSON-RPC params object               |

**Returns:**
- `(any, nil)` on success -- the JSON-RPC `result` field
- `(nil, *GatewayError)` on gateway denial -- use `errors.As` to inspect
- `(nil, error)` on network/context errors

**Retry behavior:** Retries only HTTP 503 with exponential backoff
(`base`, `base*2`, `base*4`). Non-503 errors return immediately.

### SessionID

```go
func (c *GatewayClient) SessionID() string
```

Returns the session ID (auto-generated UUID or custom).

### Options

| Option                            | Default              | Description                            |
|-----------------------------------|----------------------|----------------------------------------|
| `WithTimeout(d time.Duration)`    | `30 * time.Second`   | HTTP request timeout                   |
| `WithMaxRetries(n int)`           | `3`                  | Max retry attempts for 503             |
| `WithBackoffBase(d time.Duration)`| `1 * time.Second`    | Exponential backoff base               |
| `WithSessionID(id string)`        | Auto-generated UUID  | Custom session ID                      |
| `WithHTTPClient(hc *http.Client)` | Default with timeout | Custom HTTP client (e.g. for mTLS)     |

### Constants

```go
const (
    DefaultMaxRetries  = 3
    DefaultBackoffBase = 1 * time.Second
    DefaultTimeout     = 30 * time.Second
)
```

### GatewayError

```go
type GatewayError struct {
    Code        string         `json:"code"`
    Message     string         `json:"message"`
    Middleware  string         `json:"middleware"`
    Step        int            `json:"middleware_step"`
    DecisionID  string         `json:"decision_id"`
    TraceID     string         `json:"trace_id"`
    Details     map[string]any `json:"details,omitempty"`
    Remediation string         `json:"remediation,omitempty"`
    DocsURL     string         `json:"docs_url,omitempty"`
    HTTPStatus  int            `json:"-"`
}
```

`GatewayError` implements `error`. The `Error()` method returns
`"gateway error <code>: <message>"`.

`HTTPStatus` is populated from the HTTP response, not JSON body (excluded
from serialization with `json:"-"`).

### Error Handling Pattern (Go)

```go
result, err := client.Call(ctx, "tavily_search", map[string]any{"query": "test"})
if err != nil {
    var ge *mcpgateway.GatewayError
    if errors.As(err, &ge) {
        switch ge.Code {
        case "authz_policy_denied":
            log.Printf("OPA denied at step %d: %s", ge.Step, ge.Message)
        case "ratelimit_exceeded":
            log.Printf("Rate limited -- implement backoff")
        case "dlp_credentials_detected":
            log.Printf("DLP blocked credentials: %s", ge.Remediation)
        default:
            log.Printf("Gateway error %s: %s", ge.Code, ge.Message)
        }
        if ge.DecisionID != "" {
            log.Printf("Audit decision: %s", ge.DecisionID)
        }
    } else {
        log.Printf("Network error: %v", err)
    }
}
```

---

## Section 3: Python SDK Reference

**Package:** `mcp_gateway_sdk`
**Min Python:** 3.13
**Core dependency:** `httpx >= 0.28.0`
**Optional:** `opentelemetry-api >= 1.39.0` (install with `uv sync --project sdk/python --python 3.13 --extra otel`)

### GatewayClient

```python
class GatewayClient:
    def __init__(
        self,
        url: str,
        spiffe_id: str,
        *,
        session_id: Optional[str] = None,
        tracer: Any = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
    ) -> None: ...
```

| Parameter      | Type            | Default | Description                    |
|----------------|-----------------|---------|--------------------------------|
| `url`          | `str`           | required| Gateway base URL               |
| `spiffe_id`    | `str`           | required| SPIFFE identity for auth       |
| `session_id`   | `Optional[str]` | `None`  | Auto-generated UUID if omitted |
| `tracer`       | `Any`           | `None`  | OTel Tracer for span creation  |
| `timeout`      | `float`         | `30.0`  | HTTP timeout in seconds        |
| `max_retries`  | `int`           | `3`     | Max retry for 503              |
| `backoff_base` | `float`         | `1.0`   | Backoff base in seconds        |

### call

```python
def call(self, tool_name: str, **params: Any) -> Any: ...
```

Returns the JSON-RPC `result` field. Raises `GatewayError` on 4xx/5xx
or JSON-RPC errors. Raises `httpx.ConnectError` if gateway unreachable.

### close

```python
def close(self) -> None: ...
```

Closes the underlying `httpx.Client`.

### Context Manager

```python
with GatewayClient(url="...", spiffe_id="...") as client:
    result = client.call("tavily_search", query="test")
```

### session_id

```python
client.session_id  # str -- read-only property
```

### GatewayError

```python
class GatewayError(Exception):
    code: str            # Machine-readable error code
    message: str         # Human-readable description
    middleware: str       # Middleware layer name
    step: int            # Middleware step (1-13)
    decision_id: str     # Audit decision ID
    trace_id: str        # OTel trace ID
    details: dict[str, Any]  # Optional structured data (defaults to {})
    remediation: str     # Fix guidance
    docs_url: str        # Documentation link
    http_status: int     # HTTP status code
```

### GatewayError.from_response

```python
@classmethod
def from_response(cls, http_status: int, body: dict[str, Any]) -> GatewayError: ...
```

Factory classmethod. Field mapping from JSON:

| JSON Field        | Attribute      | Fallback        |
|-------------------|----------------|-----------------|
| `code`            | `code`         | `error` field   |
| `message`         | `message`      | `reason` field  |
| `middleware`       | `middleware`   | `""`            |
| `middleware_step` | `step`         | `0`             |
| `decision_id`     | `decision_id`  | `""`            |
| `trace_id`        | `trace_id`     | `""`            |
| `details`         | `details`      | `{}`            |
| `remediation`     | `remediation`  | `""`            |
| `docs_url`        | `docs_url`     | `""`            |

### Error Handling Pattern (Python)

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

with GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
) as client:
    try:
        result = client.call("tavily_search", query="AI security")
    except GatewayError as e:
        if e.code == "authz_policy_denied":
            print(f"OPA denied at step {e.step}: {e.message}")
        elif e.code == "ratelimit_exceeded":
            print(f"Rate limited (HTTP {e.http_status})")
        elif e.code == "dlp_credentials_detected":
            print(f"DLP blocked: {e.remediation}")
        else:
            print(f"Error {e.code}: {e.message}")
    except httpx.ConnectError:
        print("Gateway unreachable")
```

### OTel Integration (Python)

```python
from opentelemetry import trace
from mcp_gateway_sdk import GatewayClient

tracer = trace.get_tracer("my-agent")
client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
    tracer=tracer,
)
```

Span name: `gateway.tool_call.<tool_name>`. Attributes set:

| Attribute              | When       | Value                    |
|------------------------|------------|--------------------------|
| `mcp.method`           | On create  | Tool name                |
| `mcp.params`           | On create  | JSON-serialized params   |
| `spiffe.id`            | On create  | Client SPIFFE ID         |
| `session.id`           | On create  | Client session ID        |
| `mcp.result.success`   | On complete| `True` or `False`        |
| `mcp.error.code`       | On error   | Error code string        |
| `mcp.error.http_status`| On error   | HTTP status code         |

---

## Section 4: Gateway API Contract

### Endpoints

| Method | Path               | Purpose                        | Auth Required |
|--------|--------------------|--------------------------------|---------------|
| POST   | `/`                | JSON-RPC 2.0 tool calls        | Yes           |
| POST   | `/data/dereference`| Response firewall handle deref  | Yes           |
| GET    | `/health`          | Health check + circuit breaker  | No            |

### Required Headers (POST /)

| Header         | Value                | Purpose                              |
|----------------|----------------------|--------------------------------------|
| `Content-Type` | `application/json`   | JSON-RPC payload encoding            |
| `X-SPIFFE-ID`  | SPIFFE identity URI  | Authentication and authorization     |
| `Authorization` | Bearer access token | External OAuth resource-server auth  |
| `X-Session-ID` | UUID                 | Session tracking, exfiltration detection |

### JSON-RPC 2.0 Wire Format

**Request:**

```json
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

| Field    | Type    | Required | Description                    |
|----------|---------|----------|--------------------------------|
| `jsonrpc`| string  | Yes      | Must be `"2.0"`                |
| `method` | string  | Yes      | MCP-spec tool invocation uses `tools/call` |
| `params` | object  | Yes      | For `tools/call`, `{"name":"<tool_name>","arguments":{...}}` |
| `id`     | integer | Yes      | Request ID (echoed in response)|

**Success Response (200):**

```json
{
  "jsonrpc": "2.0",
  "result": { "content": [{"type": "text", "text": "..."}] },
  "id": 1
}
```

**Gateway Denial Response (4xx/5xx):**

```json
{
  "code": "authz_policy_denied",
  "message": "OPA policy denied tool access",
  "middleware": "opa_policy",
  "middleware_step": 6,
  "decision_id": "550e8400-e29b-41d4-a716-446655440000",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "details": { "risk_level": "high" },
  "remediation": "Check OPA policy grants for your SPIFFE ID",
  "docs_url": ""
}
```

### Error Envelope Fields

| Field             | Type   | Always Present | Description                             |
|-------------------|--------|----------------|-----------------------------------------|
| `code`            | string | Yes            | Machine-readable error code             |
| `message`         | string | Yes            | Human-readable description              |
| `middleware`       | string | Yes            | Middleware that rejected                |
| `middleware_step` | int    | Yes            | Step number (1-13) or 0                 |
| `decision_id`     | string | Yes            | UUID for audit log cross-reference      |
| `trace_id`        | string | Yes            | OTel trace ID                           |
| `details`         | object | No             | Optional structured context             |
| `remediation`     | string | No             | Fix guidance                            |
| `docs_url`        | string | No             | Documentation link                      |

---

## Section 5: SPIFFE Identity Schema

```
spiffe://<trust-domain>/<class>/<purpose>/<env>
```

| Component      | Description          | Examples                                  |
|----------------|----------------------|-------------------------------------------|
| `trust-domain` | Organization ID      | `poc.local`                               |
| `class`        | Identity class       | `agents`, `gateways`, `services`, `spike` |
| `purpose`      | Functional name      | `mcp-client/dspy-researcher`, `precinct-gateway` |
| `env`          | Deployment env       | `dev`, `staging`, `prod`                  |

### Concrete Examples

| SPIFFE ID | Workload |
|-----------|----------|
| `spiffe://poc.local/agents/example/dev` | Development agent |
| `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` | DSPy research agent |
| `spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev` | PydanticAI research agent |
| `spiffe://poc.local/gateways/precinct-gateway/dev` | Gateway service |
| `spiffe://poc.local/spike/nexus` | SPIKE Nexus |

### OPA Wildcard Patterns

| Pattern | Matches |
|---------|---------|
| `spiffe://poc.local/agents/mcp-client/*/dev` | All MCP client agents in dev |
| `spiffe://poc.local/agents/mcp-client/*-researcher/dev` | All researcher agents |
| `spiffe://poc.local/gateways/*/dev` | All gateways in dev |

Trust domain validation is exact-match. The trust domain is configured via
`SPIFFE_TRUST_DOMAIN` (default: `poc.local`).

---

## Section 6: SPIKE Token Format

```
$SPIKE{ref:<hex>,exp:<seconds>,scope:<scope>}
```

| Component | Required | Format        | Description                            |
|-----------|----------|---------------|----------------------------------------|
| `ref`     | Yes      | Hexadecimal   | Reference to secret in SPIKE Nexus     |
| `exp`     | No       | Integer       | Token expiration in seconds            |
| `scope`   | No       | Dotted string | Required access scope (e.g. `tools.tavily.search`) |

### Examples

```
$SPIKE{ref:abc123}
$SPIKE{ref:deadbeef,exp:3600}
$SPIKE{ref:1a2b3c,exp:7200,scope:tools.s3.read}
```

### Usage in Requests

Embed SPIKE tokens anywhere a secret value is needed:

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

### Security Invariant

Token substitution is step 13 (innermost). This guarantees:
- DLP scanning (step 7) sees only `$SPIKE{...}` references, not secrets
- Audit logs (step 4) record token references, not secret values
- If any middleware rejects the request, secrets are never fetched or exposed
- No middleware upstream of step 13 ever processes actual secret values

### Scope Validation

When a scope is specified, the gateway validates it against the tool's
`required_scope` from `config/tool-registry.yaml`. Scope mismatch returns 403.

---

## Section 7: OPA Policy Patterns

The OPA policy engine runs embedded in the gateway. Policy files are loaded
from `OPA_POLICY_DIR` (default: `/config/opa`).

### Policy Files

| File                    | Package              | Purpose                         |
|-------------------------|----------------------|---------------------------------|
| `mcp_policy.rego`       | `mcp`                | Main authorization policy       |
| `context_policy.rego`   | `mcp.context`        | Context injection gating        |
| `exfiltration.rego`     | `mcp.exfiltration`   | Cross-tool exfiltration detection |
| `ui_policy.rego`        | `mcp.ui.policy`      | UI resource authorization       |
| `ui_csp_policy.rego`    | `mcp.ui.csp`         | CSP and permissions mediation   |

### Authorization Model (mcp_policy.rego)

The main `allow` decision evaluates six conditions in sequence. ALL must pass:

1. **SPIFFE ID matching** -- exact or wildcard (`*`) against grant patterns
2. **Tool authorization** -- tool in grant's `allowed_tools` list, or `"*"` wildcard
3. **Path restrictions** -- `read`/`grep` tools: path must start with `ALLOWED_BASE_PATH`
4. **Destination restrictions** -- `bash`: blocked if command contains `curl`/`wget`/`http`
5. **Step-up gating** -- if `requires_step_up=true`, step-up token must be present
6. **Session risk** -- `session.risk_score` must be below `0.7`

### Denial Reasons

| Reason                    | Meaning                              |
|---------------------------|--------------------------------------|
| `default_deny`            | No conditions evaluated              |
| `no_matching_grant`       | SPIFFE ID has no grant               |
| `tool_not_authorized`     | Tool not in allowed list             |
| `path_denied`             | File path outside allowed base       |
| `destination_denied`      | External destination blocked         |
| `step_up_required`        | Step-up token missing                |
| `session_risk_too_high`   | Session risk score >= 0.7            |

### Tool Grants (tool_grants.yaml)

```yaml
tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools:
      - read
      - grep
      - tavily_search
    max_data_classification: internal
    requires_approval_for:
      - bash
      - file_write
```

Key fields:
- `spiffe_pattern` -- SPIFFE ID or wildcard pattern
- `allowed_tools` -- list of tool names, or `["*"]` for all
- `max_data_classification` -- `public`, `internal`, `sensitive`, `confidential`
- `requires_approval_for` -- tools needing human approval

### Extending OPA Policies

To add a new tool grant:

1. Add an entry to `config/opa/tool_grants.yaml`
2. Register the tool in `config/tool-registry.yaml` with SHA-256 hash
3. Run `opa test config/opa/ -v` to verify policy tests pass
4. The gateway reloads policies automatically (embedded OPA)

### Poisoning Detection

The policy detects 7 patterns in tool descriptions:
1. `<IMPORTANT>` tags
2. `<SYSTEM>` tags
3. HTML comments (`<!-- ... -->`)
4. "before using this tool...first" injection
5. "ignore previous/all/prior instructions"
6. "you must always/first/never" commands
7. "send...to" with email/http/webhook/upload

---

## Section 8: Configuration Reference

### Gateway Core

| Variable                  | Default                | Description                     |
|---------------------------|------------------------|---------------------------------|
| `PORT`                    | `9090`                 | HTTP listen port                |
| `UPSTREAM_URL`            | `http://host.docker.internal:8081/mcp` | Backend MCP server URL |
| `MAX_REQUEST_SIZE_BYTES`  | `10485760` (10 MB)     | Max request body size           |
| `SPIFFE_MODE`             | `dev`                  | `dev` (HTTP) or `prod` (mTLS)  |
| `SPIFFE_TRUST_DOMAIN`    | `poc.local`            | SPIFFE trust domain             |
| `SPIFFE_LISTEN_PORT`     | `9443`                 | HTTPS port in prod mode         |
| `MCP_TRANSPORT_MODE`     | `mcp`                  | `mcp` (JSON-RPC) or `proxy` (reverse proxy) |
| `LOG_LEVEL`              | `info`                 | `debug`, `info`, `warn`, `error` |
| `AUDIT_LOG_PATH`         | `/var/log/gateway/audit.jsonl` | Audit log file path      |

### Guard Model (Deep Scan)

| Variable                | Default                                | Description               |
|-------------------------|----------------------------------------|---------------------------|
| `GROQ_API_KEY`          | _(required for deep scan)_             | Groq API key (fallback for GUARD_API_KEY) |
| `GUARD_MODEL_ENDPOINT`  | `https://api.groq.com/openai/v1`      | Guard model API base URL  |
| `GUARD_MODEL_NAME`      | `meta-llama/llama-prompt-guard-2-86m`  | Guard model identifier    |
| `GUARD_API_KEY`         | Falls back to `GROQ_API_KEY`           | Guard model API key       |
| `DEEP_SCAN_TIMEOUT`     | `5`                                    | Guard model timeout (seconds) |
| `DEEP_SCAN_FALLBACK`    | `fail_closed`                          | `fail_closed` or `fail_open` |

### DLP

| Variable                | Default                | Description                     |
|-------------------------|------------------------|---------------------------------|
| `DLP_INJECTION_POLICY`  | _(empty -- uses YAML)_ | `block` or `flag` for injection category |

DLP policy per category:
- `credentials` = `block` (SECURITY INVARIANT -- not overridable via env var)
- `injection` = `flag` (overridable via `DLP_INJECTION_POLICY`)
- `pii` = `flag` (YAML-only change)

### Rate Limiting

| Variable           | Default (code) | Default (docker-compose) | Description          |
|--------------------|----------------|--------------------------|----------------------|
| `RATE_LIMIT_RPM`   | `600`          | `60`                     | Requests/min per agent |
| `RATE_LIMIT_BURST` | `100`          | `10`                     | Burst allowance      |

### Circuit Breaker

| Variable                    | Default | Description                              |
|-----------------------------|---------|------------------------------------------|
| `CIRCUIT_FAILURE_THRESHOLD` | `5`     | Consecutive failures before open         |
| `CIRCUIT_RESET_TIMEOUT`     | `30`    | Seconds before half-open                 |
| `CIRCUIT_SUCCESS_THRESHOLD` | `2`     | Successes to close from half-open        |

### SPIKE Integration

| Variable          | Default    | Description                           |
|-------------------|------------|---------------------------------------|
| `SPIKE_NEXUS_URL` | _(empty)_  | SPIKE Nexus HTTPS URL for mTLS       |

### Session Persistence (KeyDB)

| Variable       | Default    | Description                             |
|----------------|------------|-----------------------------------------|
| `KEYDB_URL`    | _(empty)_  | KeyDB/Redis URL (`redis://host:6379`)   |
| `SESSION_TTL`  | `3600`     | Session TTL in seconds                  |

### Response Firewall

| Variable     | Default | Description                          |
|--------------|---------|--------------------------------------|
| `HANDLE_TTL` | `300`   | Data handle expiry in seconds        |

### OpenTelemetry

| Variable                        | Default                | Description              |
|---------------------------------|------------------------|--------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`  | _(empty -- disabled)_  | OTLP gRPC endpoint       |
| `OTEL_SERVICE_NAME`            | `precinct-gateway` | Service name in traces   |

### Configuration Files

| File                             | Purpose                            |
|----------------------------------|------------------------------------|
| `config/tool-registry.yaml`      | Tool definitions with SHA-256 hashes |
| `config/opa/tool_grants.yaml`    | SPIFFE ID -> tool authorization    |
| `config/opa/mcp_policy.rego`     | Main OPA authorization policy      |
| `config/destinations.yaml`       | Destination allowlist for step-up   |
| `config/risk_thresholds.yaml`    | Risk scoring + DLP policy config   |
| `config/spiffe-ids.yaml`         | SPIFFE ID schema reference         |
| `config/ui.yaml`                 | MCP-UI security configuration      |

---

## Section 9: Common Patterns

### Pattern 1: Basic Tool Call (Go)

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"

    "github.com/precinct-dev/precinct/sdk/go/mcpgateway"
)

func main() {
    client := mcpgateway.NewClient(
        "http://localhost:9090",
        "spiffe://poc.local/agents/example/dev",
    )

    result, err := client.Call(context.Background(), "tavily_search", map[string]any{
        "query":       "AI security best practices",
        "max_results": 5,
    })
    if err != nil {
        var ge *mcpgateway.GatewayError
        if errors.As(err, &ge) {
            log.Fatalf("gateway denied: %s (step %d): %s", ge.Code, ge.Step, ge.Message)
        }
        log.Fatal(err)
    }
    fmt.Println(result)
}
```

### Pattern 2: Basic Tool Call (Python)

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

with GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
) as client:
    try:
        result = client.call("tavily_search", query="AI security", max_results=5)
        print(result)
    except GatewayError as e:
        print(f"Denied: {e.code} - {e.message}")
        print(f"Remediation: {e.remediation}")
```

### Pattern 3: Error Handling with Retry Logic (Go)

```go
client := mcpgateway.NewClient(
    "http://localhost:9090",
    "spiffe://poc.local/agents/my-agent/dev",
    mcpgateway.WithMaxRetries(5),
    mcpgateway.WithBackoffBase(500*time.Millisecond),
    mcpgateway.WithTimeout(10*time.Second),
)

result, err := client.Call(ctx, "tavily_search", map[string]any{"query": "test"})
if err != nil {
    var ge *mcpgateway.GatewayError
    if errors.As(err, &ge) {
        switch {
        case ge.HTTPStatus == 429:
            // Rate limited -- caller should implement own backoff
            log.Printf("Rate limited. Decision: %s", ge.DecisionID)
        case ge.HTTPStatus == 403:
            // Policy denied -- check ge.Code for specific reason
            log.Printf("Denied by %s: %s", ge.Middleware, ge.Code)
        case ge.HTTPStatus == 503:
            // All retries exhausted
            log.Printf("Service unavailable after retries: %s", ge.Code)
        }
    }
    return
}
```

### Pattern 4: Error Handling with Retry Logic (Python)

```python
import time
from mcp_gateway_sdk import GatewayClient, GatewayError

client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/my-agent/dev",
    max_retries=5,
    backoff_base=0.5,
    timeout=10.0,
)

try:
    result = client.call("tavily_search", query="test")
except GatewayError as e:
    if e.http_status == 429:
        # Rate limited -- SDK does NOT auto-retry 429; caller must backoff
        wait_time = 60  # wait for rate limit window to reset
        time.sleep(wait_time)
    elif e.http_status == 403:
        print(f"Policy denied: {e.code} at step {e.step}")
        print(f"Decision ID: {e.decision_id}")
    elif e.http_status == 503:
        print(f"Service unavailable after retries: {e.code}")
finally:
    client.close()
```

### Pattern 5: mTLS Setup with go-spiffe (Go)

```go
package main

import (
    "context"
    "crypto/tls"
    "log"
    "net/http"

    "github.com/precinct-dev/precinct/sdk/go/mcpgateway"
    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
    ctx := context.Background()

    // Obtain X.509 SVID from SPIRE agent
    source, err := workloadapi.NewX509Source(ctx)
    if err != nil {
        log.Fatalf("failed to create X509 source: %v", err)
    }
    defer source.Close()

    // Build mTLS HTTP client
    tlsConfig := &tls.Config{
        GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
            svid, err := source.GetX509SVID()
            if err != nil {
                return nil, err
            }
            cert := tls.Certificate{
                Certificate: make([][]byte, len(svid.Certificates)),
                PrivateKey:  svid.PrivateKey,
            }
            for i, c := range svid.Certificates {
                cert.Certificate[i] = c.Raw
            }
            return &cert, nil
        },
        RootCAs: source.GetX509BundleForTrustDomain(
            source.GetX509SVID().ID.TrustDomain(),
        ).X509Authorities(),
    }

    httpClient := &http.Client{
        Transport: &http.Transport{TLSClientConfig: tlsConfig},
    }

    client := mcpgateway.NewClient(
        "https://gateway.internal:9090",
        "spiffe://poc.local/agents/my-agent/prod",
        mcpgateway.WithHTTPClient(httpClient),
    )

    result, err := client.Call(ctx, "tavily_search", map[string]any{
        "query": "production search",
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Result: %v", result)
}
```

### Pattern 6: SPIKE Token Usage

Embed SPIKE token references in tool parameters instead of raw secrets:

```go
// Go
result, err := client.Call(ctx, "tavily_search", map[string]any{
    "query":   "sensitive topic",
    "api_key": "$SPIKE{ref:abc123,exp:3600,scope:tools.tavily.search}",
})
```

```python
# Python
result = client.call(
    "tavily_search",
    query="sensitive topic",
    api_key="$SPIKE{ref:abc123,exp:3600,scope:tools.tavily.search}",
)
```

The gateway replaces `$SPIKE{...}` with the actual secret at step 13.
The secret never appears in logs, DLP scans, or audit records.

### Pattern 7: Session Management

Use the same session ID across related calls for session-level tracking:

```go
// Go -- session ID is auto-generated and reused
client := mcpgateway.NewClient(url, spiffeID)
fmt.Println(client.SessionID()) // e.g. "550e8400-e29b-41d4-a716-446655440000"

// All calls share the session ID
client.Call(ctx, "read", map[string]any{"file_path": "/data/report.txt"})
client.Call(ctx, "tavily_search", map[string]any{"query": "analysis"})
```

```python
# Python -- same pattern
client = GatewayClient(url="...", spiffe_id="...")
print(client.session_id)  # auto-generated UUID

# All calls share the session ID
client.call("read", file_path="/data/report.txt")
client.call("tavily_search", query="analysis")
```

To share a session across multiple client instances:

```go
// Go
sessionID := "shared-session-123"
client1 := mcpgateway.NewClient(url, spiffeID, mcpgateway.WithSessionID(sessionID))
client2 := mcpgateway.NewClient(url, spiffeID, mcpgateway.WithSessionID(sessionID))
```

```python
# Python
session_id = "shared-session-123"
client1 = GatewayClient(url=url, spiffe_id=spiffe_id, session_id=session_id)
client2 = GatewayClient(url=url, spiffe_id=spiffe_id, session_id=session_id)
```

### Pattern 8: OTel Tracing Integration (Python)

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

# Set up OTel
provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://localhost:4317"))
)
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("my-agent")

# Pass tracer to client
client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/my-agent/dev",
    tracer=tracer,
)

# Each call() creates a span with tool name, params, and result status
result = client.call("tavily_search", query="traced search")
```

### Pattern 9: Concurrent Calls (Go)

`GatewayClient` is safe for concurrent use (request ID uses `atomic.Int64`):

```go
client := mcpgateway.NewClient(url, spiffeID)

var wg sync.WaitGroup
queries := []string{"query A", "query B", "query C"}

for _, q := range queries {
    wg.Add(1)
    go func(query string) {
        defer wg.Done()
        result, err := client.Call(context.Background(), "tavily_search", map[string]any{
            "query": query,
        })
        if err != nil {
            log.Printf("Error for %q: %v", query, err)
            return
        }
        log.Printf("Result for %q: %v", query, result)
    }(q)
}

wg.Wait()
```

---

## Section 10: Security Invariants

These invariants MUST NOT be violated under any circumstances. They are
architectural decisions that protect the security posture of the system.

### Invariant 1: Token Substitution Position

Token substitution (step 13) MUST be the innermost middleware -- the last
step before the proxy. Moving it earlier would expose actual secrets to
DLP scanning, audit logging, and all other middleware.

**If violated:** Secrets appear in audit logs, DLP scans, and potentially
in error responses sent back to agents.

### Invariant 2: DLP Credentials Always Block

The `credentials` DLP category MUST always use `block` policy. This is
hardcoded and not overridable via environment variable. The only way to
change it is editing `config/risk_thresholds.yaml` directly.

**Design rationale:** Credential leakage through tool calls must always be
blocked. Making this toggleable via env var risks accidental degradation.

**If violated:** Credentials (API keys, passwords, tokens) could leak
through tool call parameters to upstream MCP servers.

### Invariant 3: Audit Log Position

Audit logging (step 4) sees requests BEFORE policy enforcement. This is
intentional -- the audit trail records what was attempted, enabling
forensic analysis of denied requests.

### Invariant 4: Circuit Breaker Scope

The circuit breaker is per-tool, not global. One failing upstream tool
does not prevent calls to other healthy tools.

### Invariant 5: Rate Limit Scope

Rate limiting is per-SPIFFE-ID. Each agent identity has an independent
token bucket. One agent hitting its limit does not affect other agents.

### Invariant 6: Trust Domain Validation

SPIFFE trust domain validation uses exact string matching. A SPIFFE ID
under `poc.local` will not match a policy for `poc.local.evil` or
`evil.poc.local`. The trust domain is configured once via
`SPIFFE_TRUST_DOMAIN` and cannot be changed at runtime.

---

## Section 11: Error Code Catalog

All 25 gateway error codes from `internal/gateway/middleware/error_codes.go`,
plus 3 SDK-only codes.

| Code | Step | HTTP | Remediation |
|------|------|------|-------------|
| `request_too_large` | 1 | 413 | Reduce payload or increase `MAX_REQUEST_SIZE_BYTES` |
| `auth_missing_identity` | 3 | 401 | Add `X-SPIFFE-ID` header with valid SPIFFE identity |
| `auth_invalid_identity` | 3 | 401 | Use a SPIFFE ID under the configured trust domain |
| `auth_invalid_bearer_token` | 3 | 401 | Refresh the OAuth bearer token and verify issuer/audience/scope/JWKS config |
| `registry_tool_unknown` | 5 | 403 | Register the tool in `config/tool-registry.yaml` |
| `registry_hash_mismatch` | 5 | 403 | Re-register tool with correct hash; investigate tampering |
| `authz_policy_denied` | 6 | 403 | Check OPA policy grants for this agent/tool combination |
| `authz_no_matching_grant` | 6 | 403 | Add a grant in OPA policy for this SPIFFE ID and tool |
| `authz_tool_not_found` | 6 | 403 | Add the tool to the OPA data document |
| `dlp_credentials_detected` | 7 | 403 | Use `$SPIKE{ref:...}` tokens instead of raw credentials |
| `dlp_injection_blocked` | 7 | 403 | Remove injection patterns; configurable via `DLP_INJECTION_POLICY` |
| `dlp_pii_blocked` | 7 | 403 | Remove PII or adjust policy in `risk_thresholds.yaml` |
| `exfiltration_detected` | 8 | 403 | Review session data flow for legitimate cross-tool usage |
| `stepup_denied` | 9 | 403 | Request elevated privileges or reduce operation risk |
| `stepup_approval_required` | 9 | 403 | Obtain human-in-the-loop approval |
| `stepup_guard_blocked` | 9 | 403 | Modify request content to pass guard model safety checks |
| `stepup_destination_blocked` | 9 | 403 | Add destination to `config/destinations.yaml` |
| `deepscan_blocked` | 10 | 403 | Modify request to pass deep scan safety checks |
| `deepscan_unavailable_fail_closed` | 10 | 503 | Ensure guard model API is accessible, or set `DEEP_SCAN_FALLBACK=fail_open` |
| `ratelimit_exceeded` | 11 | 429 | Wait and retry; limits: `RATE_LIMIT_RPM`/min with `RATE_LIMIT_BURST` burst |
| `circuit_open` | 12 | 503 | Wait for `CIRCUIT_RESET_TIMEOUT` (default 30s), then retry |
| `ui_capability_denied` | -- | 403 | Add grants in `ui_capability_grants.yaml` |
| `ui_resource_blocked` | -- | 403 | Ensure resource passes content controls |
| `mcp_transport_failed` | -- | 502 | Ensure upstream MCP server is running and accessible |
| `mcp_request_failed` | -- | 502 | Check upstream MCP server logs |
| `mcp_invalid_response` | -- | 502 | Verify MCP server returns valid JSON-RPC 2.0 responses |

SDK-only codes (generated client-side, not from gateway):
- `invalid_response` -- gateway returned non-JSON
- `jsonrpc_error` -- JSON-RPC response contained `error` field
- `unknown` -- error response could not be parsed

### Error Code Decision Tree

```
Is HTTP status 401?
  -> auth_missing_identity or auth_invalid_identity
     Fix: Add/fix X-SPIFFE-ID header

Is HTTP status 403?
  -> Check error code:
     authz_*          -> OPA policy issue. Check grants.
     registry_*       -> Tool not registered or hash mismatch.
     dlp_*            -> Sensitive content in request. Remove or use SPIKE tokens.
     exfiltration_*   -> Suspicious cross-tool data flow.
     stepup_*         -> Risk too high. Need approval or guard model check.
     deepscan_blocked -> Content flagged by LLM safety model.
     ui_*             -> MCP-UI capability not granted.

Is HTTP status 413?
  -> request_too_large. Reduce payload.

Is HTTP status 429?
  -> ratelimit_exceeded. Backoff and retry.

Is HTTP status 502?
  -> mcp_*. Upstream MCP server issue.

Is HTTP status 503?
  -> circuit_open or deepscan_unavailable_fail_closed.
     SDK auto-retries 503 with exponential backoff.
```

---

## Appendix A: Middleware Chain Quick Reference

| Step | Name                | Can Block | HTTP Code | Purpose |
|------|---------------------|-----------|-----------|---------|
| 1    | Request Size Limit  | Yes       | 413       | Reject oversized payloads |
| 2    | Body Capture        | No        | --        | Capture body for downstream |
| 3    | SPIFFE Auth         | Yes       | 401       | Validate caller identity from SPIFFE or OAuth bearer JWT |
| 4    | Audit Log           | No        | --        | Record attempt with decision_id |
| 5    | Tool Registry Verify| Yes       | 403       | Anti-poisoning hash check |
| 6    | OPA Policy          | Yes       | 403       | Authorization evaluation |
| 7    | DLP Scanner         | Yes       | 403       | Credential/injection/PII scan |
| 8    | Session Context     | Yes       | 403       | Exfiltration detection |
| 9    | Step-Up Gating      | Yes       | 403       | Risk scoring + guard pre-check |
| 10   | Deep Scan           | Yes       | 403/503   | LLM safety classifier |
| 11   | Rate Limiter        | Yes       | 429       | Per-agent token bucket |
| 12   | Circuit Breaker     | Yes       | 503       | Upstream failure protection |
| 13   | Token Substitution  | Yes       | 403       | Replace $SPIKE{} with secrets |
| --   | Response Firewall   | Post-proxy| --        | Replace sensitive response data |

---

## Appendix B: Risk Scoring

The gateway uses a 4-dimensional risk scoring rubric. Each dimension
scores 0-3, for a total range of 0-12.

| Score Range | Action                                    |
|-------------|-------------------------------------------|
| 0-3         | Fast path -- no additional friction        |
| 4-6         | Step-up gating -- destination check + guard model |
| 7-9         | Human approval required (HTTP 403 stub)    |
| 10-12       | Deny by default                           |

Guard model thresholds:
- `injection_threshold`: 0.30 (block if probability > 30%)
- `jailbreak_threshold`: 0.30 (block if probability > 30%)

---

## Appendix C: Tool Registry Format

```yaml
tools:
  - name: "tavily_search"
    description: "Search the web using Tavily API"
    hash: "76c6b3d8..."
    input_schema:
      type: "object"
      required: ["query"]
      properties:
        query:
          type: "string"
    allowed_destinations:
      - "api.tavily.com"
    risk_level: "medium"
    requires_step_up: false
    required_scope: "tools.tavily.search"
```

Hash computation: `SHA-256(description + canonical_json(input_schema))`

The registry supports hot-reload via filesystem watching. When the YAML
file changes, the registry reloads automatically without gateway restart.

When `TOOL_REGISTRY_PUBLIC_KEY` is set (production), updates require a
companion `.sig` file for attestation verification.
