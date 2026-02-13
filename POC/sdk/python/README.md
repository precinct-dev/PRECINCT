# MCP Gateway Python SDK

Python client library for making MCP JSON-RPC tool calls through the Agentic AI Security Gateway. Framework-independent -- works with PydanticAI, DSPy, LangGraph, CrewAI, or raw HTTP.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Context Manager Usage](#context-manager-usage)
- [API Reference](#api-reference)
  - [GatewayClient](#gatewayclient)
  - [GatewayClient.call](#gatewayclientcall)
  - [GatewayClient.close](#gatewayclientclose)
  - [GatewayClient.session\_id](#gatewayclientsession_id)
- [Error Handling](#error-handling)
  - [GatewayError](#gatewayerror)
  - [GatewayError.from\_response](#gatewayerrorfrom_response)
  - [Error Handling Patterns](#error-handling-patterns)
- [Error Code Catalog](#error-code-catalog)
- [OpenTelemetry Integration](#opentelemetry-integration)
- [Wire Format](#wire-format)
- [Logging](#logging)
- [Retry Behavior](#retry-behavior)

---

## Installation

**Requirements:** Python >= 3.10

Install from the local SDK directory:

```bash
pip install ./sdk/python
```

Or using `uv`:

```bash
uv pip install ./sdk/python
```

**Core dependency:** [httpx](https://www.python-httpx.org/) >= 0.28.0

**Optional dependencies:**

```bash
# OpenTelemetry tracing support
pip install ./sdk/python[otel]

# Development dependencies (pytest, httpx)
pip install ./sdk/python[dev]
```

---

## Quick Start

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
)

try:
    result = client.call("tavily_search", query="AI security", max_results=5)
    print(result)
except GatewayError as e:
    print(f"Denied: {e.code} - {e.message}")
    print(f"Remediation: {e.remediation}")
finally:
    client.close()
```

---

## Context Manager Usage

`GatewayClient` implements `__enter__` and `__exit__`, so it can be used as a context manager. The underlying `httpx.Client` is closed automatically when the `with` block exits.

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

with GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
) as client:
    result = client.call("tavily_search", query="test")
    print(result)
```

This is equivalent to calling `client.close()` in a `finally` block. The context manager is the recommended pattern for production use.

---

## Runtime Helpers

The SDK also exposes shared runtime helpers used by the demo agents:

- `load_dotenv()` -- loads `.env` values when `python-dotenv` is installed
- `normalize_model_name()` -- strips provider prefixes from model IDs
- `resolve_model_api_key_ref()` -- resolves explicit SPIKE Bearer refs or builds from `GROQ_LM_SPIKE_REF`
- `setup_observability()` -- OpenTelemetry setup helper
- `configure_dspy_gateway_lms()` -- configures DSPy gateway LM and optional reasoning LM (RLM)

```python
from mcp_gateway_sdk import configure_dspy_gateway_lms, load_dotenv

load_dotenv()
lm, rlm = configure_dspy_gateway_lms(
    llm_model="groq/openai/gpt-oss-20b",
    gateway_url="http://localhost:9090",
    model_provider="groq",
    rlm_model="openai/o1-mini",  # optional
)
```

---

## API Reference

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

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | `str` | *required* | Gateway base URL (e.g., `"http://localhost:9090"`). |
| `spiffe_id` | `str` | *required* | SPIFFE identity string sent as the `X-SPIFFE-ID` header. Used by the gateway for authentication and authorization. |
| `session_id` | `Optional[str]` | `None` | Custom session ID. If `None`, a UUID is auto-generated. Sent as `X-Session-ID` header. Use the same session ID across related calls for session tracking. |
| `tracer` | `Any` | `None` | Optional OpenTelemetry `Tracer` instance. When provided, the client creates spans for each `call()`. See [OpenTelemetry Integration](#opentelemetry-integration). |
| `timeout` | `float` | `30.0` | HTTP request timeout in seconds. Passed to the underlying `httpx.Client`. |
| `max_retries` | `int` | `3` | Maximum retry attempts for HTTP 503 responses. Set to `0` to disable retries. |
| `backoff_base` | `float` | `1.0` | Base for exponential backoff between retries, in seconds. Actual delay is `backoff_base * 2^attempt`. |

**Example with all parameters:**

```python
from opentelemetry import trace

tracer = trace.get_tracer("my-agent")

client = GatewayClient(
    url="http://gateway.internal:9090",
    spiffe_id="spiffe://poc.local/agents/my-agent/prod",
    session_id="session-abc-123",
    tracer=tracer,
    timeout=15.0,
    max_retries=5,
    backoff_base=0.5,
)
```

---

### GatewayClient.call

```python
def call(self, tool_name: str, **params: Any) -> Any: ...
```

Call a tool through the security gateway. Constructs an MCP JSON-RPC request, sends it to the gateway, handles errors (raising `GatewayError` for denials), and returns the raw JSON-RPC `result` on success.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tool_name` | `str` | MCP tool name (e.g., `"tavily_search"`, `"read"`, `"bash"`). |
| `**params` | `Any` | Keyword arguments that become the JSON-RPC `params` dict. |

**Returns:** The `result` field from the JSON-RPC response (typically a `dict` or other JSON-deserializable value).

**Raises:**
- `GatewayError` -- on HTTP 4xx/5xx responses or JSON-RPC errors from the gateway.
- `httpx.ConnectError` -- if the gateway is unreachable.

**Examples:**

```python
# Simple call
result = client.call("tavily_search", query="AI security best practices")

# Multiple parameters
result = client.call("tavily_search", query="quantum computing", max_results=10)

# File read
content = client.call("read", file_path="/etc/hostname")

# SPIKE token reference (late-binding secret)
result = client.call("tavily_search", query="$SPIKE{ref:deadbeef,exp:3600,scope:search}")
```

---

### GatewayClient.close

```python
def close(self) -> None: ...
```

Close the underlying `httpx.Client`. Call this when you are done making requests to release HTTP connections. This is called automatically when using the context manager pattern.

---

### GatewayClient.session_id

```python
client.session_id  # str
```

The session ID for this client instance. Either the value passed to the constructor or an auto-generated UUID string. This value is sent as the `X-Session-ID` header on every request and is used by the gateway for session-level tracking (e.g., exfiltration detection across tool calls).

---

## Error Handling

### GatewayError

```python
class GatewayError(Exception):
    code: str
    message: str
    middleware: str
    step: int
    decision_id: str
    trace_id: str
    details: dict[str, Any]
    remediation: str
    docs_url: str
    http_status: int
```

Raised when the gateway returns an error response. All attributes match the unified JSON error envelope.

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `code` | `str` | Machine-readable error code (e.g., `"authz_policy_denied"`). See [Error Code Catalog](#error-code-catalog). |
| `message` | `str` | Human-readable description of the error. |
| `middleware` | `str` | Name of the middleware layer that rejected the request (e.g., `"OPA Policy"`, `"DLP Scanner"`). |
| `step` | `int` | Middleware step number in the 13-layer chain (1-13). |
| `decision_id` | `str` | Audit decision ID for cross-referencing with gateway audit logs. |
| `trace_id` | `str` | OpenTelemetry trace ID for distributed tracing correlation. |
| `details` | `dict[str, Any]` | Optional structured data (risk scores, matched patterns, etc.). Defaults to `{}`. |
| `remediation` | `str` | Guidance on how to fix the issue (e.g., `"Remove credentials from request payload"`). |
| `docs_url` | `str` | Link to relevant documentation. |
| `http_status` | `int` | HTTP status code from the response (e.g., `403`, `429`, `503`). |

---

### GatewayError.from_response

```python
@classmethod
def from_response(cls, http_status: int, body: dict[str, Any]) -> GatewayError: ...
```

Factory classmethod that parses a `GatewayError` from the HTTP response JSON body. Falls back gracefully when fields are missing (e.g., legacy response formats).

**Expected JSON envelope:**

```json
{
    "code": "authz_policy_denied",
    "message": "OPA policy denied access to tool 'bash'",
    "middleware": "OPA Policy",
    "middleware_step": 6,
    "decision_id": "dec-abc-123",
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "details": {"risk_level": "critical"},
    "remediation": "Request step-up authentication for bash access",
    "docs_url": "https://docs.example.com/opa-policy"
}
```

**Field mapping (JSON envelope -> GatewayError attribute):**

| JSON Field | GatewayError Attribute | Fallback |
|------------|----------------------|----------|
| `code` | `code` | `error` field |
| `message` | `message` | `reason` field |
| `middleware` | `middleware` | `""` |
| `middleware_step` | `step` | `0` |
| `decision_id` | `decision_id` | `""` |
| `trace_id` | `trace_id` | `""` |
| `details` | `details` | `None` -> `{}` |
| `remediation` | `remediation` | `""` |
| `docs_url` | `docs_url` | `""` |

**Usage (typically internal, but available for custom HTTP handling):**

```python
import httpx

resp = httpx.post("http://localhost:9090", json=payload, headers=headers)
if resp.status_code >= 400:
    raise GatewayError.from_response(resp.status_code, resp.json())
```

---

### Error Handling Patterns

**Basic error handling:**

```python
from mcp_gateway_sdk import GatewayClient, GatewayError

with GatewayClient(url="http://localhost:9090",
                    spiffe_id="spiffe://poc.local/agents/example/dev") as client:
    try:
        result = client.call("tavily_search", query="test")
    except GatewayError as e:
        print(f"Error: {e.code} (HTTP {e.http_status})")
        print(f"Step: {e.step}, Middleware: {e.middleware}")
        print(f"Message: {e.message}")
        if e.remediation:
            print(f"Fix: {e.remediation}")
```

**Handling specific error codes:**

```python
try:
    result = client.call("bash", command="ls")
except GatewayError as e:
    if e.code == "authz_policy_denied":
        print(f"OPA denied at step {e.step}: {e.message}")
        print(f"Decision ID: {e.decision_id}")
    elif e.code == "ratelimit_exceeded":
        print(f"Rate limited (HTTP {e.http_status})")
    elif e.code == "dlp_credentials_detected":
        print(f"DLP blocked credentials: {e.remediation}")
    elif e.code == "stepup_approval_required":
        print(f"Step-up auth required: {e.message}")
    elif e.code == "circuit_open":
        print(f"Circuit breaker open for this tool")
    else:
        print(f"Error {e.code}: {e.message}")
except httpx.ConnectError:
    print("Gateway unreachable")
```

**Inspecting all error attributes (debugging):**

```python
try:
    result = client.call("tavily_search", query="test")
except GatewayError as e:
    print(f"Code:        {e.code}")
    print(f"Message:     {e.message}")
    print(f"Middleware:  {e.middleware}")
    print(f"Step:        {e.step}")
    print(f"HTTP Status: {e.http_status}")
    print(f"Decision ID: {e.decision_id}")
    print(f"Trace ID:    {e.trace_id}")
    print(f"Details:     {e.details}")
    print(f"Remediation: {e.remediation}")
    print(f"Docs URL:    {e.docs_url}")
```

---

## Error Code Catalog

All error codes are defined in the gateway's middleware layer. Each code maps to a specific middleware step and HTTP status.

| Code | Middleware Step | HTTP Status | Description |
|------|---------------|-------------|-------------|
| `auth_missing_identity` | 3 (SPIFFE Auth) | 401 | No SPIFFE identity provided in `X-SPIFFE-ID` header. |
| `auth_invalid_identity` | 3 (SPIFFE Auth) | 401 | SPIFFE identity format is invalid or trust domain mismatch. |
| `registry_tool_unknown` | 5 (Tool Registry) | 403 | Tool name not found in the approved tool registry. |
| `registry_hash_mismatch` | 5 (Tool Registry) | 403 | Tool definition hash does not match the registered hash. |
| `authz_policy_denied` | 6 (OPA Policy) | 403 | OPA policy explicitly denied the request. |
| `authz_no_matching_grant` | 6 (OPA Policy) | 403 | No tool grant found for this SPIFFE ID and tool combination. |
| `authz_tool_not_found` | 6 (OPA Policy) | 403 | Tool not found in OPA policy data. |
| `dlp_credentials_detected` | 7 (DLP Scanner) | 403 | Credentials detected in request payload (AWS keys, API keys, passwords, private keys). Always blocked. |
| `dlp_injection_blocked` | 7 (DLP Scanner) | 403 | Prompt injection pattern blocked by DLP policy. |
| `dlp_pii_blocked` | 7 (DLP Scanner) | 403 | PII pattern blocked by DLP policy. |
| `exfiltration_detected` | 8 (Session Context) | 403 | Cross-tool data exfiltration pattern detected within session. |
| `stepup_denied` | 9 (Step-Up Gating) | 403 | Step-up authentication denied. |
| `stepup_approval_required` | 9 (Step-Up Gating) | 403 | Human approval required before proceeding. |
| `stepup_guard_blocked` | 9 (Step-Up Gating) | 403 | Guard model (Prompt Guard 2) blocked the request. |
| `stepup_destination_blocked` | 9 (Step-Up Gating) | 403 | Destination URL blocked by step-up policy. |
| `deepscan_blocked` | 10 (Deep Scan) | 403 | Deep scan model detected a threat in the request. |
| `deepscan_unavailable_fail_closed` | 10 (Deep Scan) | 503 | Deep scan service unavailable; fail-closed policy applied. |
| `ratelimit_exceeded` | 11 (Rate Limiting) | 429 | Per-SPIFFE-ID rate limit exceeded. Implements token bucket via KeyDB. |
| `circuit_open` | 12 (Circuit Breaker) | 503 | Circuit breaker is open for this tool (too many upstream failures). |
| `request_too_large` | 1 (Request Size) | 413 | Request body exceeds the maximum allowed size (default 10 MB). |
| `ui_capability_denied` | -- (UI Gating) | 403 | UI capability not granted for this SPIFFE identity. |
| `ui_resource_blocked` | -- (UI Gating) | 403 | UI resource access blocked. |
| `mcp_transport_failed` | -- (MCP Proxy) | 502 | Transport-level failure connecting to the MCP server. |
| `mcp_request_failed` | -- (MCP Proxy) | 502 | MCP server returned a JSON-RPC error. |
| `mcp_invalid_response` | -- (MCP Proxy) | 502 | Malformed response received from the MCP server. |

**Note:** The SDK also uses three internal codes not defined in the gateway:
- `invalid_response` -- raised client-side when the gateway returns non-JSON.
- `jsonrpc_error` -- raised client-side when the JSON-RPC response contains an `error` field.
- `unknown` -- raised client-side when the error response cannot be parsed.

---

## OpenTelemetry Integration

When a `tracer` is provided to the constructor, the client automatically creates OpenTelemetry spans for each `call()` invocation.

**Setup:**

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

**Span details:**

| Field | Value |
|-------|-------|
| Span name | `gateway.tool_call.<tool_name>` (e.g., `gateway.tool_call.tavily_search`) |

**Span attributes set on creation:**

| Attribute | Value |
|-----------|-------|
| `mcp.method` | The tool name |
| `mcp.params` | JSON-serialized params dict |
| `spiffe.id` | The client's SPIFFE ID |
| `session.id` | The client's session ID |

**Span attributes set on completion:**

| Attribute | Condition | Value |
|-----------|-----------|-------|
| `mcp.result.success` | On success | `True` |
| `mcp.result.success` | On error | `False` |
| `mcp.error.code` | On `GatewayError` | The error code string |
| `mcp.error.http_status` | On `GatewayError` | The HTTP status code |
| `mcp.error` | On other exceptions | String representation |

**Install the optional OTel dependency:**

```bash
pip install ./sdk/python[otel]
# Installs: opentelemetry-api >= 1.39.0
```

---

## Wire Format

The SDK constructs MCP JSON-RPC 2.0 requests. Understanding the wire format is useful for debugging.

**Request (sent by SDK):**

```python
# client.call("tavily_search", query="AI security", max_results=5)
# produces this HTTP request:

# POST / HTTP/1.1
# Content-Type: application/json
# X-SPIFFE-ID: spiffe://poc.local/agents/example/dev
# X-Session-ID: <auto-generated UUID or custom>

{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "tavily_search",
        "arguments": {
            "query": "AI security",
            "max_results": 5
        }
    },
    "id": 1
}
```

**Note:** The SDK uses MCP-spec compliant `tools/call`. Some deployments may still accept
the deprecated shortcut `method="<tool_name>"`, but `tools/call` is the recommended and
portable wire format.

**Success response:**

```json
{
    "jsonrpc": "2.0",
    "result": {
        "data": "..."
    },
    "id": 1
}
```

The SDK returns the value of the `result` field.

**Error response (HTTP 4xx/5xx):**

```json
{
    "code": "authz_policy_denied",
    "message": "OPA policy denied access",
    "middleware": "OPA Policy",
    "middleware_step": 6,
    "decision_id": "dec-abc-123",
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "details": {},
    "remediation": "Check OPA policy grants for your SPIFFE ID",
    "docs_url": ""
}
```

The SDK parses this into a `GatewayError` exception via `GatewayError.from_response()`.

**Headers sent on every request:**

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | `application/json` | Required for JSON-RPC |
| `X-SPIFFE-ID` | Client's SPIFFE identity | Authentication (step 3) |
| `X-Session-ID` | Client's session ID | Session tracking (step 8) |

---

## Logging

The SDK uses Python's standard `logging` module.

**Logger name:** `mcp_gateway_sdk`

**Log messages:**

| Level | When | Message Pattern |
|-------|------|-----------------|
| `WARNING` | Retry attempt for HTTP 503 | `Tool %s returned 503 (attempt %d/%d). Retrying in %.1fs. Code: %s` |
| `ERROR` | All retries exhausted for HTTP 503 | `Tool %s returned 503 after %d attempts. Giving up. Code: %s` |

**Configuring log output:**

```python
import logging

# See SDK retry messages
logging.getLogger("mcp_gateway_sdk").setLevel(logging.WARNING)

# Or attach a handler for custom formatting
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
logging.getLogger("mcp_gateway_sdk").addHandler(handler)
```

---

## Retry Behavior

The SDK automatically retries HTTP 503 (Service Unavailable) responses with exponential backoff. All other HTTP error codes are raised immediately without retry.

**Retry parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | `3` | Maximum retry attempts. Total attempts = `max_retries + 1`. |
| `backoff_base` | `1.0` | Base delay in seconds. |

**Backoff schedule (with defaults):**

| Attempt | Delay Before Retry |
|---------|-------------------|
| 1 (initial) | -- |
| 2 (1st retry) | 1.0s (`1.0 * 2^0`) |
| 3 (2nd retry) | 2.0s (`1.0 * 2^1`) |
| 4 (3rd retry) | 4.0s (`1.0 * 2^2`) |

**Disabling retries:**

```python
client = GatewayClient(
    url="http://localhost:9090",
    spiffe_id="spiffe://poc.local/agents/example/dev",
    max_retries=0,  # No retries -- fail immediately on 503
)
```

**Which errors are retried:**

| HTTP Status | Retried? | Reason |
|-------------|----------|--------|
| 503 | Yes | Service temporarily unavailable (circuit breaker, deep scan down) |
| 401 | No | Authentication failure -- retrying won't help |
| 403 | No | Authorization denied -- retrying won't help |
| 429 | No | Rate limited -- SDK does not implement rate limit backoff (caller should) |
| 502 | No | Upstream MCP server failure |
| Other 4xx/5xx | No | Non-transient errors |
