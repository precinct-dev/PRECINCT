# Public Transport

PRECINCT now supports a dual-listener runtime in `SPIFFE_MODE=prod`:

- Internal listener: HTTPS + mTLS on `SPIFFE_LISTEN_PORT`
- Public listener: HTTP on `PUBLIC_LISTEN_HOST:PUBLIC_LISTEN_PORT`

The public listener is intended to sit behind a TLS-terminating ingress or reverse proxy. External clients should never connect directly over plaintext outside the trusted cluster or host boundary.

## Startup Gates

When the public listener is enabled in `SPIFFE_MODE=prod`, startup fails unless the OAuth resource-server configuration is present and parses successfully:

- `OAUTH_RESOURCE_SERVER_CONFIG_PATH`

This ensures the public listener only comes up when bearer-token authentication can actually be enforced by the gateway.

## Environment

Key public-listener settings:

- `PUBLIC_LISTEN_HOST`
  Default: `0.0.0.0`
- `PUBLIC_LISTEN_PORT`
  Default: `9090`
- `PUBLIC_ROUTE_ALLOWLIST`
  Default: `/,/health,/.well-known/oauth-protected-resource,/v1/auth/token-exchange`
- `PUBLIC_TRUSTED_PROXY_CIDRS`
  Default: empty

`PUBLIC_TRUSTED_PROXY_CIDRS` is reserved for deployments that need to trust `X-Forwarded-For` from specific ingress proxies. Leave it empty unless the ingress path and proxy chain are well understood.

## Route Model

The public listener exposes only exact allowlisted paths. Non-allowlisted paths return `404`, not `403`, to reduce public surface discovery.

Current public behavior:

- `/health` is served directly and does not require authentication
- `/` reuses the normal protected gateway middleware chain, so public MCP requests still go through auth, audit, OPA, DLP, session, step-up, rate limiting, and proxy handling
- Paths that are listed but not yet implemented still return `404`
- `/data/dereference`, `/admin/*`, and model-plane endpoints are not mounted on the public listener

## TLS Termination

Recommended deployment shape:

1. Internet client connects to ingress/load balancer over HTTPS.
2. Ingress terminates TLS.
3. Ingress forwards to PRECINCT public listener over trusted internal HTTP.
4. Internal workloads continue using the SPIFFE mTLS listener.

This keeps external bearer-token traffic and internal SPIFFE traffic separated without weakening the internal mTLS posture.

## Example

```bash
export SPIFFE_MODE=prod
export SPIFFE_LISTEN_PORT=9443
export PUBLIC_LISTEN_HOST=0.0.0.0
export PUBLIC_LISTEN_PORT=9090
export PUBLIC_ROUTE_ALLOWLIST="/,/health,/.well-known/oauth-protected-resource"
export OAUTH_RESOURCE_SERVER_CONFIG_PATH=/config/oauth-resource-server.yaml
```

With a local reverse proxy or port-forward in place:

```bash
curl -s http://127.0.0.1:9090/health
curl -i http://127.0.0.1:9090/not-allowlisted
```

Expected results:

- `/health` returns `200`
- unknown public paths return `404`
- `POST /` reaches the normal gateway middleware chain and will deny unauthenticated requests with the usual gateway error envelope
