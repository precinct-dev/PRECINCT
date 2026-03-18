# OAuth Protected Resource Metadata

The PRECINCT gateway exposes a discovery endpoint at
`/.well-known/oauth-protected-resource` that tells external MCP clients how to
authenticate. The response follows the
[RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) protected resource metadata
pattern and aligns with
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) resource indicators.

## Endpoint

```
GET /.well-known/oauth-protected-resource
```

- **Authentication:** None required. This is a public discovery endpoint.
- **Method:** GET only (other methods return 405).
- **Cache-Control:** `public, max-age=3600`

## Response Fields

| Field                    | Type       | Description |
|--------------------------|------------|-------------|
| `resource`               | string     | The audience / resource indicator the client must request in its token (RFC 8707). |
| `authorization_servers`  | `string[]` | Issuer base URL(s) for the Authorization Server(s) the client should use. |
| `scopes_supported`       | `string[]` | Scopes relevant to tool access. Omitted when no scopes are configured. |
| `mcp_endpoint`           | string     | The MCP JSON-RPC endpoint path (e.g., `/`). |

All values are derived from `config/oauth-resource-server.yaml` at gateway startup.
Nothing is hardcoded.

## Example Response

```json
{
  "resource": "gateway",
  "authorization_servers": ["http://mock-oauth-issuer:8088"],
  "scopes_supported": ["mcp:tools"],
  "mcp_endpoint": "/"
}
```

## curl Examples

### Fetch metadata (local dev)

```bash
curl -s http://localhost:9090/.well-known/oauth-protected-resource | jq .
```

### Fetch metadata (production public listener)

```bash
curl -s https://gateway.example.com/.well-known/oauth-protected-resource | jq .
```

### Programmatic client flow

A typical external MCP client uses this endpoint as follows:

```bash
# 1. Discover OAuth requirements
META=$(curl -s http://localhost:9090/.well-known/oauth-protected-resource)
ISSUER=$(echo "$META" | jq -r '.authorization_servers[0]')
AUDIENCE=$(echo "$META" | jq -r '.resource')
SCOPES=$(echo "$META" | jq -r '.scopes_supported | join(" ")')

# 2. Obtain a token from the Authorization Server
#    (client_credentials flow shown; your AS may differ)
TOKEN=$(curl -s "${ISSUER}/oauth/token" \
  -d grant_type=client_credentials \
  -d client_id=YOUR_CLIENT_ID \
  -d client_secret=YOUR_CLIENT_SECRET \
  -d "audience=${AUDIENCE}" \
  -d "scope=${SCOPES}" | jq -r '.access_token')

# 3. Call the MCP endpoint with the bearer token
MCP_ENDPOINT=$(echo "$META" | jq -r '.mcp_endpoint')
curl -s "http://localhost:9090${MCP_ENDPOINT}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
```

## Configuration

The metadata is sourced from the OAuth resource server configuration file
(default path: `/config/oauth-resource-server.yaml`, overridable via the
`OAUTH_RESOURCE_SERVER_CONFIG_PATH` environment variable).

```yaml
oauth_resource_server:
  issuer: "http://mock-oauth-issuer:8088"
  audience: "gateway"
  jwks_url: "http://mock-oauth-issuer:8088/jwks.json"
  required_scopes:
    - "mcp:tools"
```

| YAML field         | Metadata field           |
|--------------------|--------------------------|
| `issuer`           | `authorization_servers`  |
| `audience`         | `resource`               |
| `required_scopes`  | `scopes_supported`       |

The `mcp_endpoint` is always `/` (the gateway's JSON-RPC root).

## When OAuth Is Not Configured

If the gateway starts without an OAuth resource server configuration (no config
file, `OAUTH_RESOURCE_SERVER_CONFIG_PATH` unset or empty), the endpoint returns
**404 Not Found**. This accurately signals that the resource does not advertise
OAuth requirements.
