# Mock OAuth Issuer

Test OAuth 2.0 authorization server with in-memory token storage.
Used for testing the gateway's token exchange endpoint without
an external identity provider.

## Endpoints

- `GET /jwks.json` -- JSON Web Key Set
- `POST /token` -- Token issuance
- `POST /introspect` -- Token introspection (RFC 7662)

## Usage

Built and deployed automatically by the Docker Compose stack.
