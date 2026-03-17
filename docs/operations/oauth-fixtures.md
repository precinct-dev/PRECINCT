# Mock OAuth Fixtures

## Purpose

This document is the canonical fixture contract for `OC-3j6e` and downstream OAuth
integration stories.

The stack starts a deterministic OAuth issuer service in compose so integration tests can
request:

- JWKS (`GET /jwks.json`)
- JWT access tokens (`POST /token`)
- Opaque-token introspection (`POST /introspect`)

## Execution Contract

Run the stack:

```
docker network create phoenix-observability-network || true
docker compose -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.phoenix.yml \
  -f deploy/compose/docker-compose.oauth-fixtures.yml \
  up -d --wait
```

Run the integration tests that validate the fixture contract:

```
go test -tags=integration ./tests/integration -run OAuthExternal
```

Stop and clean up:

```
docker compose -f deploy/compose/docker-compose.yml \
  -f deploy/compose/docker-compose.phoenix.yml \
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
