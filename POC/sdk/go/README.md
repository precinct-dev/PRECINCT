# PRECINCT Gateway -- Go SDK

A Go client for making MCP JSON-RPC tool calls through the PRECINCT Gateway.
The SDK handles JSON-RPC envelope construction, required HTTP headers, structured
error parsing, retry logic with exponential backoff, and session management.

**Package:** `github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway`

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Configuration Options](#configuration-options)
- [Error Handling](#error-handling)
- [Error Code Catalog](#error-code-catalog)
- [Required HTTP Headers](#required-http-headers)
- [JSON-RPC Wire Format](#json-rpc-wire-format)
- [Advanced Usage](#advanced-usage)
- [Constants](#constants)

## Installation

```bash
go get github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway
```

**Minimum Go version:** 1.24.6

**External dependencies:** `github.com/google/uuid` (session ID generation)

For local development with a `replace` directive:

```go
// In your go.mod
replace github.com/RamXX/agentic_reference_architecture/POC/sdk/go => ../path/to/sdk/go
```

## Quick Start

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway"
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

## API Reference

### NewClient

```go
func NewClient(url, spiffeID string, opts ...Option) *GatewayClient
```

Creates a new gateway client.

| Parameter  | Type       | Description                                              |
|------------|------------|----------------------------------------------------------|
| `url`      | `string`   | Gateway base URL (e.g., `"http://localhost:9090"`)       |
| `spiffeID` | `string`   | SPIFFE identity sent in the `X-SPIFFE-ID` header         |
| `opts`     | `...Option`| Zero or more configuration options (see [Configuration Options](#configuration-options)) |

**Returns:** `*GatewayClient` -- configured client with an auto-generated session ID (UUID).

```go
// Minimal
client := mcpgateway.NewClient("http://localhost:9090", "spiffe://poc.local/agents/my-agent/dev")

// With options
client := mcpgateway.NewClient(
    "http://localhost:9090",
    "spiffe://poc.local/agents/my-agent/dev",
    mcpgateway.WithTimeout(10*time.Second),
    mcpgateway.WithMaxRetries(5),
)
```

### Call

```go
func (c *GatewayClient) Call(ctx context.Context, toolName string, params map[string]any) (any, error)
```

Invokes a tool through the gateway using the MCP JSON-RPC protocol.

| Parameter  | Type              | Description                                            |
|------------|-------------------|--------------------------------------------------------|
| `ctx`      | `context.Context` | Context for cancellation and deadlines                 |
| `toolName` | `string`          | MCP tool name (e.g., `"tavily_search"`, `"read"`)      |
| `params`   | `map[string]any`  | Tool arguments (becomes `params.arguments` in `tools/call`) |

**Returns:**

- `(any, nil)` -- On success, the JSON-RPC `"result"` field (typically a `map[string]any`).
- `(nil, *GatewayError)` -- On gateway denial. Use `errors.As` to inspect.
- `(nil, error)` -- On network or context errors (not retried).

**Retry behavior:**

- Retries only HTTP 503 (Service Unavailable) responses.
- Uses exponential backoff: `base`, `base*2`, `base*4`, ...
- Default: 3 retries with 1s base (delays of 1s, 2s, 4s).
- Respects `ctx` cancellation during backoff waits.
- Non-503 gateway errors (401, 403, 429, etc.) are returned immediately without retry.

### SessionID

```go
func (c *GatewayClient) SessionID() string
```

Returns the session ID used by this client. Auto-generated as a UUID unless overridden
with `WithSessionID`.

### CallModelChat

```go
func (c *GatewayClient) CallModelChat(ctx context.Context, req ModelChatRequest) (map[string]any, error)
```

Sends an OpenAI-compatible chat completion request through PRECINCT Gateway model egress.

`CallModelChat` is a mediated gateway API only:

- Default endpoint: `/openai/v1/chat/completions`
- Custom `ModelChatRequest.Endpoint` values must stay gateway-relative
- Absolute `http://` and `https://` URLs are rejected to prevent silent bypass of gateway enforcement

The Go SDK does not provide a direct-to-provider chat helper. If you intentionally need unmanaged
direct egress, use your own `http.Client` so that call site remains explicit and cannot be mistaken
for PRECINCT-mediated traffic.

```go
resp, err := client.CallModelChat(context.Background(), mcpgateway.ModelChatRequest{
    Model:     "llama-3.3-70b-versatile",
    Messages:  []map[string]any{{"role": "user", "content": "hello"}},
    Provider:  "groq",
    APIKeyRef: "Bearer $SPIKE{ref:deadbeef,exp:3600}",
    Endpoint:  "/openai/v1/chat/completions",
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(resp["id"])
```

This returns a plain `error` for client-side contract violations such as absolute endpoints, and a
`*GatewayError` when the gateway itself denies the request.

## Configuration Options

All options are passed to `NewClient` as functional options.

| Option                               | Default           | Description                                          |
|---------------------------------------|-------------------|------------------------------------------------------|
| `WithTimeout(d time.Duration)`        | `30 * time.Second`| HTTP request timeout                                 |
| `WithMaxRetries(n int)`               | `3`               | Max retry attempts for 503 responses                 |
| `WithBackoffBase(d time.Duration)`    | `1 * time.Second` | Exponential backoff base. Delays: base, base*2, base*4, ... |
| `WithSessionID(id string)`            | Auto-generated UUID | Custom session ID for the `X-Session-ID` header   |
| `WithHTTPClient(hc *http.Client)`     | Default `http.Client` with timeout | Custom HTTP client (e.g., for mTLS via go-spiffe) |

```go
client := mcpgateway.NewClient(
    "http://localhost:9090",
    "spiffe://poc.local/agents/my-agent/dev",
    mcpgateway.WithTimeout(10*time.Second),
    mcpgateway.WithMaxRetries(5),
    mcpgateway.WithBackoffBase(500*time.Millisecond),
    mcpgateway.WithSessionID("my-custom-session-id"),
)
```

## Error Handling

All gateway denials are returned as `*GatewayError`. Use `errors.As` to type-assert:

```go
result, err := client.Call(ctx, "tavily_search", params)
if err != nil {
    var ge *mcpgateway.GatewayError
    if errors.As(err, &ge) {
        // Structured gateway denial
        switch ge.Code {
        case "authz_policy_denied":
            log.Printf("OPA denied: %s (step %d)", ge.Message, ge.Step)
        case "ratelimit_exceeded":
            log.Printf("Rate limited, retry after backoff")
        case "dlp_credentials_detected":
            log.Printf("DLP blocked credentials in request")
        default:
            log.Printf("Gateway error %s: %s", ge.Code, ge.Message)
        }

        // Cross-reference with audit logs
        if ge.DecisionID != "" {
            log.Printf("Audit decision: %s", ge.DecisionID)
        }

        // Distributed tracing correlation
        if ge.TraceID != "" {
            log.Printf("Trace: %s", ge.TraceID)
        }
    } else {
        // Network error, context cancelled, etc.
        log.Printf("Non-gateway error: %v", err)
    }
}
```

### GatewayError Fields

```go
type GatewayError struct {
    Code        string         `json:"code"`               // Machine-readable error code (e.g., "authz_policy_denied")
    Message     string         `json:"message"`            // Human-readable error description
    Middleware  string         `json:"middleware"`          // Which middleware layer rejected the request
    Step        int            `json:"middleware_step"`     // Middleware step number in the chain (1-13)
    DecisionID  string         `json:"decision_id"`        // Audit decision ID for cross-referencing audit logs
    TraceID     string         `json:"trace_id"`           // OpenTelemetry trace ID for distributed tracing
    Details     map[string]any `json:"details,omitempty"`  // Optional structured data (risk scores, etc.)
    Remediation string         `json:"remediation,omitempty"` // How to resolve the error
    DocsURL     string         `json:"docs_url,omitempty"` // Link to relevant documentation
    HTTPStatus  int            `json:"-"`                  // HTTP status code (from HTTP layer, not in JSON body)
}
```

`GatewayError` implements the `error` interface:

```go
func (e *GatewayError) Error() string
// Returns: "gateway error <code>: <message>"
```

**Note:** The `HTTPStatus` field is populated from the HTTP response status code, not from the
JSON body. It is excluded from JSON serialization (`json:"-"`).

## Error Code Catalog

All 25 machine-readable error codes, organized by middleware layer.

### Request Size (step 1)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `request_too_large` | 413 | Request payload exceeds the 10 MB size limit |

### SPIFFE Authentication (step 3)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `auth_missing_identity` | 401 | No SPIFFE ID provided in `X-SPIFFE-ID` header |
| `auth_invalid_identity` | 401 | SPIFFE ID is malformed or not in the trust domain |

### Tool Registry (step 5)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `registry_tool_unknown` | 403 | Tool name is not in the approved registry |
| `registry_hash_mismatch` | 403 | Tool definition hash does not match registered hash |

### OPA Authorization (step 6)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `authz_policy_denied` | 403 | OPA policy explicitly denied the request |
| `authz_no_matching_grant` | 403 | No OPA policy grant matched the request |
| `authz_tool_not_found` | 403 | Tool not found in OPA policy rules |

### DLP Scanner (step 7)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `dlp_credentials_detected` | 403 | Credentials detected in payload (AWS keys, API keys, passwords, private keys) |
| `dlp_injection_blocked` | 403 | Prompt injection pattern blocked by DLP policy |
| `dlp_pii_blocked` | 403 | PII pattern blocked by DLP policy |

### Session Context / Exfiltration (step 8)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `exfiltration_detected` | 403 | Data exfiltration pattern detected in session |

### Step-Up Gating (step 9)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `stepup_denied` | 403 | Step-up authentication required but denied |
| `stepup_approval_required` | 403 | Human approval required for this operation |
| `stepup_guard_blocked` | 403 | Guard model (Prompt Guard 2) blocked the request |
| `stepup_destination_blocked` | 403 | Destination blocked by step-up policy |

### Deep Scan (step 10)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `deepscan_blocked` | 403 | Deep scan model detected malicious content |
| `deepscan_unavailable_fail_closed` | 503 | Deep scan service unavailable, fail-closed policy applied |

### Rate Limiting (step 11)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ratelimit_exceeded` | 429 | Per-identity rate limit exceeded |

### Circuit Breaker (step 12)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `circuit_open` | 503 | Circuit breaker is open due to upstream failures |

### UI Capability Gating

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `ui_capability_denied` | 403 | UI capability not granted to this identity |
| `ui_resource_blocked` | 403 | UI resource access blocked |

### MCP Transport (proxy)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `mcp_transport_failed` | 502/503 | Transport-level failure (connection timeout, network error) |
| `mcp_request_failed` | 502 | MCP server returned a JSON-RPC error |
| `mcp_invalid_response` | 502 | Malformed or unparseable response from MCP server |

## Required HTTP Headers

The client automatically sets these headers on every request:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Type` | `application/json` | JSON-RPC payload encoding |
| `X-SPIFFE-ID` | SPIFFE identity URI | Identity assertion for authentication and authorization |
| `X-Session-ID` | UUID | Session tracking for audit trail and risk accumulation |

## JSON-RPC Wire Format

The SDK constructs and parses standard JSON-RPC 2.0 envelopes.

### Request

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

The `id` field is an auto-incrementing 64-bit integer, safe for concurrent use
(backed by `atomic.Int64`).

**Note:** The recommended (MCP-spec compliant) invocation format is `method="tools/call"`.
Some gateways may still support the deprecated shortcut `method="<tool_name>"`, but the SDK
uses `tools/call` for portability.

### Success Response

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

The `result` field is returned directly by `Call` as `any` (typically `map[string]any`).

### Error Response (JSON-RPC level)

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "tool execution failed"
  },
  "id": 1
}
```

JSON-RPC level errors are wrapped as `*GatewayError` with code `"jsonrpc_error"`.

### Gateway Denial Response (HTTP level)

Gateway denials return HTTP 4xx/5xx with a structured JSON body:

```json
{
  "code": "authz_policy_denied",
  "message": "OPA policy denied access to tool 'bash'",
  "middleware": "opa",
  "middleware_step": 6,
  "decision_id": "abc-123",
  "trace_id": "def-456",
  "remediation": "Request step-up authentication for bash access",
  "docs_url": "https://docs.example.com/opa-policies"
}
```

This body is parsed into `*GatewayError` automatically.

## Advanced Usage

### Custom HTTP Client for mTLS

In production, use mTLS with SPIFFE workload identities via `go-spiffe`:

```go
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"

	"github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway"
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
		RootCAs: source.GetX509BundleForTrustDomain(source.GetX509SVID().ID.TrustDomain()).X509Authorities(),
	}

	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// Use the mTLS client with the SDK
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

### Context with Timeout

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

result, err := client.Call(ctx, "tavily_search", map[string]any{
    "query": "time-sensitive search",
})
// err may be context.DeadlineExceeded if the call takes longer than 5s
```

### Concurrent Calls

`GatewayClient` is safe for concurrent use. The internal request ID uses `atomic.Int64`,
so multiple goroutines can call `Call` simultaneously:

```go
client := mcpgateway.NewClient(
    "http://localhost:9090",
    "spiffe://poc.local/agents/my-agent/dev",
)

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

### Disabling Retries

For demo or testing scenarios where immediate responses are preferred:

```go
client := mcpgateway.NewClient(
    "http://localhost:9090",
    "spiffe://poc.local/agents/example/dev",
    mcpgateway.WithMaxRetries(0), // No retries
)
```

## Constants

```go
const (
    DefaultMaxRetries  = 3                // Default max retry attempts for 503 responses
    DefaultBackoffBase = 1 * time.Second  // Default exponential backoff base duration
    DefaultTimeout     = 30 * time.Second // Default HTTP request timeout
)
```
