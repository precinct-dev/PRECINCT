# Token Exchange Endpoint

The PRECINCT gateway exposes a token exchange endpoint at
`/v1/auth/token-exchange` that allows third-party tools without SPIFFE sidecars
to exchange an external credential (e.g., an API key) for a short-lived JWT
bound to a SPIFFE identity. The JWT is then accepted by the gateway's
SPIFFEAuth middleware for subsequent MCP requests.

## Endpoint

```
POST /v1/auth/token-exchange
```

- **Authentication:** None required (public endpoint).
- **Method:** POST only (other methods return 405).
- **Content-Type:** `application/json`

## Request Body

| Field            | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `credential_type`| string | Yes      | The type of credential being presented (e.g., `api_key`). |
| `credential`     | string | Yes      | The plaintext credential value. |
| `requested_ttl`  | string | No       | Desired token lifetime as a Go duration (e.g., `5m`, `30m`). Clamped to the configured maximum. Defaults to `15m` if omitted. |

## Response Body (200 OK)

| Field        | Type   | Description |
|--------------|--------|-------------|
| `token`      | string | A signed JWT (HS256) bound to the matched SPIFFE identity. |
| `expires_in` | int    | Token lifetime in seconds. |
| `token_type` | string | Always `Bearer`. |

## Error Response

All errors return a JSON body with `error` (machine-readable code) and
`message` (human-readable description).

| HTTP Status | Error Code                  | Description |
|-------------|-----------------------------|-------------|
| 400         | `missing_fields`            | `credential_type` or `credential` is empty. |
| 400         | `invalid_body`              | Request body is not valid JSON. |
| 400         | `invalid_ttl`               | `requested_ttl` is not a valid Go duration. |
| 401         | `auth_credential_rejected`  | Credential did not match any configured entry. |
| 405         | `method_not_allowed`        | HTTP method is not POST. |
| 500         | `mint_failed`               | Internal error during JWT signing. |

## JWT Claims

Tokens issued by this endpoint contain the following claims:

| Claim                  | Description |
|------------------------|-------------|
| `jti`                  | Unique token ID (32-char hex, from `crypto/rand`). |
| `sub`                  | The SPIFFE ID mapped to the credential. |
| `iss`                  | `precinct-gateway` |
| `aud`                  | `precinct-gateway` |
| `exp`                  | Expiration time (Unix epoch). |
| `iat`                  | Issued-at time (Unix epoch). |
| `precinct_auth_method` | Always `token_exchange`. |

## curl Examples

### Exchange a credential for a token (local dev)

```bash
curl -s -X POST http://localhost:9090/v1/auth/token-exchange \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type": "api_key",
    "credential": "your-api-key-here"
  }' | jq .
```

### Exchange with a custom TTL

```bash
curl -s -X POST http://localhost:9090/v1/auth/token-exchange \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type": "api_key",
    "credential": "your-api-key-here",
    "requested_ttl": "5m"
  }' | jq .
```

### Full flow: exchange then call MCP

```bash
# 1. Exchange credential for a token
TOKEN=$(curl -s -X POST http://localhost:9090/v1/auth/token-exchange \
  -H "Content-Type: application/json" \
  -d '{
    "credential_type": "api_key",
    "credential": "your-api-key-here"
  }' | jq -r '.token')

# 2. Use the token to call an MCP endpoint
curl -s http://localhost:9090/ \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}' | jq .
```

## Configuration

Credentials are configured in `config/token-exchange.yaml` (path overridable
via `TOKEN_EXCHANGE_CONFIG_PATH` environment variable).

```yaml
credentials:
  - credential_type: "api_key"
    credential_hash: "$2a$10$..."   # bcrypt hash of the API key
    spiffe_id: "spiffe://poc.local/external/my-tool"

default_ttl: "15m"
max_ttl: "1h"
```

### Generating bcrypt hashes

```bash
# Using htpasswd (Apache utilities)
htpasswd -nbBC 10 "" 'your-secret' | cut -d: -f2

# Using Python
echo -n 'your-secret' | python3 -c \
  "import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt()).decode())"
```

### Environment variables

| Variable                      | Required | Description |
|-------------------------------|----------|-------------|
| `TOKEN_EXCHANGE_SIGNING_KEY`  | Yes      | HMAC-SHA256 signing key for issued JWTs. Must be at least 32 bytes. |
| `TOKEN_EXCHANGE_CONFIG_PATH`  | No       | Path to the credential mapping YAML. Defaults to `/config/token-exchange.yaml`. |

## Security Notes

1. **Credentials are never stored in plaintext.** The configuration file stores
   bcrypt hashes (`credential_hash`). The gateway compares incoming plaintext
   credentials against these hashes using `bcrypt.CompareHashAndPassword`.

2. **Tokens are short-lived.** Default TTL is 15 minutes, maximum is 1 hour.
   Clients should request only the TTL they need.

3. **Each token has a unique ID.** The `jti` claim is a cryptographically
   random 16-byte value (32 hex characters), generated via `crypto/rand`.

4. **Tokens are signed with HMAC-SHA256.** The signing key must be provided
   via the `TOKEN_EXCHANGE_SIGNING_KEY` environment variable and should be
   treated as a secret.

5. **The endpoint is unauthenticated.** It relies on credential verification
   (bcrypt comparison) for access control. Rate limiting at the network or
   gateway level is recommended for production deployments.

6. **Issued tokens carry `precinct_auth_method: token_exchange`.** This marker
   propagates through the middleware chain and into OPA policy input, allowing
   fine-grained authorization based on how the caller authenticated.
