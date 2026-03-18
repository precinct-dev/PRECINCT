# External OAuth MCP Client Integration Guide

This guide explains how external (non-SPIFFE) MCP clients authenticate with the
PRECINCT gateway using OAuth 2.0 bearer tokens.

## What the Gateway Does and Does Not Do

**The gateway IS:**
- An OAuth 2.0 **Resource Server** (RFC 6750). It validates bearer tokens presented
  by external clients against a configured JWKS endpoint.
- A policy enforcement point. After validating the token, the gateway maps the caller
  to an `external/*` principal and applies the full 13-layer middleware chain
  (OPA policy, DLP, rate limiting, etc.) before forwarding to the upstream MCP server.

**The gateway is NOT:**
- An OAuth **Authorization Server**. It does not issue tokens, manage user sessions,
  or host login flows. You must operate (or subscribe to) a separate Authorization
  Server (Auth0, Keycloak, Okta, etc.) that mints JWTs the gateway can verify.
- A token relay. The `Authorization` header is **stripped** before the request is
  forwarded to the upstream MCP server. The upstream never sees the bearer token.
  This is intentional -- the gateway translates external bearer identity into its
  internal principal model and enforces policy at the boundary.

## Prerequisites

1. **An external Authorization Server (AS)** that can issue JWTs with:
   - An `iss` (issuer) claim matching the gateway's `oauth_resource_server.issuer` config.
   - An `aud` (audience) claim matching `oauth_resource_server.audience` (default: `"gateway"`).
   - A `scope` or `scp` claim containing the required scopes (see [Scope Reference](#scope-reference)).
   - A `sub` (subject) claim identifying the caller. The gateway maps this to
     `spiffe://<trust-domain>/external/<subject>`.

2. **Gateway configuration** in `config/oauth-resource-server.yaml`:

   ```yaml
   oauth_resource_server:
     issuer: "https://your-as.example.com"
     audience: "gateway"
     jwks_url: "https://your-as.example.com/.well-known/jwks.json"
     required_scopes:
       - "mcp:tools"
     clock_skew_seconds: 30
     cache_ttl_seconds: 60
   ```

3. **OPA policy grants** in `config/opa/tool_grants.yaml` for the `external/*`
   SPIFFE pattern. The default grant allows `tavily_search` with per-tool scope
   enforcement:

   ```yaml
   - spiffe_pattern: "spiffe://poc.local/external/*"
     description: "External OAuth users -- minimal tools, deny-by-default"
     allowed_tools:
       - tavily_search
     max_data_classification: public
     required_scopes:
       tavily_search:
         - "mcp:tool:tavily_search"
   ```

## Discovery

Before authenticating, clients should discover the gateway's OAuth requirements
via the protected resource metadata endpoint
([RFC 9470](https://www.rfc-editor.org/rfc/rfc9470)):

```bash
curl -s http://localhost:9090/.well-known/oauth-protected-resource | jq .
```

Example response:

```json
{
  "resource": "gateway",
  "authorization_servers": ["https://your-as.example.com"],
  "scopes_supported": ["mcp:tools"],
  "mcp_endpoint": "/"
}
```

Use the returned fields to configure your token request:
- `authorization_servers[0]` -- where to request tokens.
- `resource` -- the `audience` parameter for your token request.
- `scopes_supported` -- the baseline scopes the gateway requires.
- `mcp_endpoint` -- the JSON-RPC endpoint path (always `/`).

See [OAuth Protected Resource Metadata](oauth-protected-resource.md) for full
field definitions and configuration details.

## Authentication Flow

### Step 1: Obtain a Token from Your Authorization Server

The token acquisition happens entirely outside the gateway. The example below uses
the OAuth 2.0 client credentials grant, but any grant type works as long as the
resulting JWT contains the required claims.

```bash
TOKEN=$(curl -s "https://your-as.example.com/oauth/token" \
  -d grant_type=client_credentials \
  -d client_id=YOUR_CLIENT_ID \
  -d client_secret=YOUR_CLIENT_SECRET \
  -d audience=gateway \
  -d "scope=mcp:tools mcp:tools:call mcp:tool:tavily_search" \
  | jq -r '.access_token')
```

### Step 2: List Available Tools

```bash
curl -s -X POST http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Session-ID: $(uuidgen)" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "params": {},
    "id": 1
  }' | jq .
```

Expected response (200 OK):

```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "tavily_search",
        "description": "Search the web using Tavily API",
        "inputSchema": { "..." }
      }
    ]
  },
  "id": 1
}
```

The `tools/list` method requires only the baseline `mcp:tools` scope. The gateway
validates the bearer token, maps the caller to `spiffe://<trust-domain>/external/<subject>`,
and forwards the request through the middleware chain. The tool list returned is
filtered by OPA policy -- external callers only see tools they are granted access to.

### Step 3: Call a Tool

```bash
curl -s -X POST http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Session-ID: $(uuidgen)" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "tavily_search",
      "arguments": {
        "query": "AI security best practices",
        "max_results": 5
      }
    },
    "id": 2
  }' | jq .
```

Expected response (200 OK):

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
  "id": 2
}
```

The `tools/call` method requires additional scopes beyond the baseline:
- `mcp:tools:call` -- the OPA policy requires this scope for any tool invocation.
- `mcp:tool:<tool_name>` -- per-tool scopes defined in the OPA grant's
  `required_scopes` map (e.g., `mcp:tool:tavily_search` for the `tavily_search` tool).

If any required scope is missing, the gateway returns 403 (see
[Troubleshooting](#troubleshooting)).

### Complete End-to-End Script

```bash
#!/usr/bin/env bash
set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:9090}"

# 1. Discover OAuth requirements
META=$(curl -s "${GATEWAY_URL}/.well-known/oauth-protected-resource")
ISSUER=$(echo "$META" | jq -r '.authorization_servers[0]')
AUDIENCE=$(echo "$META" | jq -r '.resource')

echo "Issuer:   ${ISSUER}"
echo "Audience: ${AUDIENCE}"

# 2. Obtain a token (client_credentials example)
TOKEN=$(curl -s "${ISSUER}/oauth/token" \
  -d grant_type=client_credentials \
  -d client_id="${CLIENT_ID}" \
  -d client_secret="${CLIENT_SECRET}" \
  -d "audience=${AUDIENCE}" \
  -d "scope=mcp:tools mcp:tools:call mcp:tool:tavily_search" \
  | jq -r '.access_token')

SESSION_ID=$(uuidgen)

# 3. List tools
echo "--- tools/list ---"
curl -s -X POST "${GATEWAY_URL}/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Session-ID: ${SESSION_ID}" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' | jq .

# 4. Call a tool
echo "--- tools/call ---"
curl -s -X POST "${GATEWAY_URL}/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Session-ID: ${SESSION_ID}" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{
      "name":"tavily_search",
      "arguments":{"query":"MCP security","max_results":3}
    },
    "id":2
  }' | jq .
```

## Scope Reference

Scopes control what an external bearer-authenticated caller can do. They are
enforced at two layers:

| Layer | Scope | Required For | Enforced By |
|-------|-------|-------------|-------------|
| Gateway | `mcp:tools` | All requests (baseline) | JWT validation middleware |
| OPA | `mcp:tools:call` | Any `tools/call` invocation | OPA `has_required_oauth_scope` rule |
| OPA | `mcp:tool:<tool_name>` | Per-tool access (e.g., `mcp:tool:tavily_search`) | OPA `per_tool_scope_satisfied` rule |

**Scope hierarchy:**
- `mcp:tools` is the gateway-level baseline. Without it, the token is rejected at
  JWT validation (HTTP 401) before reaching OPA.
- `mcp:tools:call` is required by OPA for `tools/call` requests. A token with only
  `mcp:tools` can call `tools/list` but not `tools/call`.
- `mcp:tool:<tool_name>` scopes provide per-tool granularity. They are only enforced
  when the matching OPA grant has a `required_scopes` entry for that tool. Grants
  without `required_scopes` impose no per-tool scope requirement.

**Example scope sets for common operations:**

| Operation | Required Scopes |
|-----------|----------------|
| `tools/list` (enumerate tools) | `mcp:tools` |
| `tools/call` with `tavily_search` | `mcp:tools mcp:tools:call mcp:tool:tavily_search` |

## Token Non-Passthrough

The gateway **strips** the `Authorization` header before forwarding the request to
the upstream MCP server. This is a deliberate security boundary:

- The upstream MCP server never sees the external bearer token.
- The gateway translates the JWT `sub` claim into an internal SPIFFE identity:
  `spiffe://<trust-domain>/external/<subject>`.
- The upstream sees only the translated SPIFFE identity and the gateway's advisory
  headers (`X-Precinct-Auth-Method: oauth_jwt`, `X-Precinct-Principal-Level`, etc.).

This means the upstream MCP server does not need to understand OAuth at all. It
receives a pre-authenticated, pre-authorized request from the gateway.

## Security Considerations

### TLS Termination

In production, all external traffic to the gateway **must** be TLS-terminated before
reaching the gateway's HTTP listener. The recommended architecture:

```
Internet --> [TLS Termination (Ingress/LB)] --> [Gateway HTTP :9090]
```

The gateway's public listener (port 9090) serves plain HTTP within the cluster.
TLS is handled by the ingress controller or load balancer in front of it. See the
[Public Edge Deployment Runbook](operations/public-edge.md) for full ingress
configuration.

Never expose the gateway's HTTP listener directly to the internet without TLS
termination.

### Route Allowlist

The public edge exposes only three routes:

| Path | Method | Purpose |
|------|--------|---------|
| `/` | POST | MCP JSON-RPC endpoint |
| `/health` | GET | Health check (no auth required) |
| `/.well-known/oauth-protected-resource` | GET | OAuth discovery |

All administrative endpoints (`/admin/*`, `/openai/v1/chat/completions`,
`/data/dereference`, `/v1/auth/token-exchange`) are excluded from the public
ingress and accessible only via the internal mTLS listener. If any of these routes
appear in a public-facing ingress, treat it as a security incident.

### Rate Limiting

External clients are subject to the same per-identity rate limiting as internal
agents. Rate limits are applied per mapped SPIFFE ID
(`spiffe://<trust-domain>/external/<subject>`), so each external user has an
independent token bucket.

Two complementary layers are recommended:

1. **Edge (ingress):** Coarse per-IP rate limiting via NGINX annotations to prevent
   volumetric abuse before it reaches the gateway.
2. **Application (gateway):** Fine-grained per-identity rate limiting with session
   awareness (default: 600 rpm, burst 100).

See the [Rate Limiting](operations/public-edge.md#edge-rate-limiting) section of the
public edge runbook for configuration details.

### Token Lifetime

Keep token lifetimes short. The gateway caches JWKS keys (default: 60 seconds), but
does not maintain a token revocation list. Short-lived tokens (5-15 minutes) limit
the window of exposure if a token is compromised.

### Principle of Least Privilege

Request only the scopes your client needs. If your client only calls `tools/list`,
request `mcp:tools` alone. If it calls `tavily_search`, request `mcp:tools
mcp:tools:call mcp:tool:tavily_search`. Do not request wildcard or unused scopes.

## Troubleshooting

### 401 `auth_missing_identity`

The request has no `Authorization` header and no `X-SPIFFE-ID` header (in dev mode)
or no client certificate (in prod mode).

**Fix:** Add `Authorization: Bearer <token>` to your request.

### 401 `auth_invalid_bearer_token`

The bearer token failed JWT validation. Common causes:
- Token is expired (`exp` claim in the past).
- Token issuer (`iss`) does not match the configured `oauth_resource_server.issuer`.
- Token audience (`aud`) does not match `oauth_resource_server.audience`.
- Token signature cannot be verified against the JWKS at `oauth_resource_server.jwks_url`.
- Token is missing a required scope listed in `oauth_resource_server.required_scopes`
  (e.g., `mcp:tools`).

**Fix:** Mint a fresh token from your Authorization Server ensuring the `iss`, `aud`,
and `scope` claims match the gateway's resource server configuration. Use the
discovery endpoint to confirm expected values:

```bash
curl -s http://localhost:9090/.well-known/oauth-protected-resource | jq .
```

### 403 `authz_no_matching_grant`

OPA found no grant entry matching the caller's SPIFFE ID and the requested tool.
For external OAuth callers, the mapped identity is
`spiffe://<trust-domain>/external/<subject>`.

**Fix:** Ensure `config/opa/tool_grants.yaml` has a grant with
`spiffe_pattern: "spiffe://<trust-domain>/external/*"` that includes the requested
tool in `allowed_tools`.

### 403 `authz_policy_denied`

OPA matched a grant but denied the request. For external callers, this typically
means a missing OAuth scope:
- Missing `mcp:tools:call` scope when calling `tools/call`.
- Missing per-tool scope (e.g., `mcp:tool:tavily_search`) when the grant has
  `required_scopes` for that tool.

**Fix:** Request the missing scope(s) from your Authorization Server and mint a new
token.

### 403 `principal_level_insufficient`

The caller's principal level (external = level 4) is too low for the requested
action. External callers cannot perform destructive or messaging operations
regardless of tool grants.

**Fix:** This action requires a higher-privilege identity (owner or agent level).
External callers cannot escalate their principal level.

### 429 `ratelimit_exceeded`

Per-identity rate limit exceeded.

**Fix:** Reduce request frequency or wait before retrying. Default limits:
600 requests per minute with burst allowance of 100.

### 404 on `/.well-known/oauth-protected-resource`

The gateway does not have an OAuth resource server configuration loaded.

**Fix:** Ensure `config/oauth-resource-server.yaml` exists and
`OAUTH_RESOURCE_SERVER_CONFIG_PATH` points to it (or use the default path).

## Related Documentation

- [OAuth Protected Resource Metadata](oauth-protected-resource.md) -- Discovery endpoint details
- [API Reference](api-reference.md) -- Full endpoint and error code catalog
- [Public Edge Deployment Runbook](operations/public-edge.md) -- Production ingress configuration
- [Sidecar Identity](sidecar-identity.md) -- SPIFFE-based internal authentication (alternative to OAuth)
