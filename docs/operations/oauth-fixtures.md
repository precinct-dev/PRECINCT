# Mock OAuth Fixtures

## Purpose

This document is the canonical fixture contract for `OC-3j6e` and downstream OAuth
integration stories.

The stack starts a deterministic OAuth issuer service in compose so integration tests can
request:

- JWKS (`GET /jwks.json`)
- JWT access tokens (`POST /token`)
- Opaque-token introspection (`POST /introspect`)
- Gateway bearer-auth e2e with upstream header observation

## Execution Contract

Run the stack:

```
make phoenix-up
docker compose --profile mock -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.oauth-fixtures.yml \
  up -d --wait
```

The OAuth overlay also sets:

- `OAUTH_RESOURCE_SERVER_CONFIG_PATH=/config/oauth-resource-server.yaml`
- `MCP_TRANSPORT_MODE=proxy`

That proxy-mode override is deliberate for the bearer-auth e2e path. It lets the mock MCP
server report whether it saw an inbound `Authorization` header so the integration test can
prove token non-passthrough end to end.

Run the host-side contract tests:

```
go test -tags=integration ./tests/integration -run OAuthExternal
```

Run the compose-network bearer-auth e2e proof:

```
tests/e2e/compose_oauth_external.sh
```

That script runs from a temporary container on the compose network, so it does not depend on
host publication of `mock-oauth-issuer:8088`.

Stop and clean up:

```
make phoenix-down
docker compose --profile mock -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.oauth-fixtures.yml \
  down -v
```

## Service Surface

- `GET /jwks.json`
- `POST /token`
- `POST /introspect`

## Notes

- The fixture intentionally stores opaque tokens in-memory and rotates keys per container start.
- JWTs are signed as HS256 and expose the matching key as `kid` in both token header and JWKS.
- The mock MCP server returns `X-Mock-Authorization: <none>` and `X-Mock-Precinct-Auth-Method: oauth_jwt`
  during the OAuth e2e path when bearer auth succeeds and the gateway strips the inbound token
  before proxying upstream.
- The local Kubernetes overlay includes a `mock-oauth-issuer` Deployment and Service in the
  `gateway` namespace so cluster validation uses the same resource-server config path.
