# Content Scanner

HTTP extension sidecar implementing the PRECINCT pluggable content scanner
interface. The gateway's deep-scan middleware delegates to this service for
LLM-based content analysis.

## Interface

- `POST /scan` -- accepts a JSON payload, returns a classification result
- Pluggable `Scanner` interface for custom analysis backends

## Usage

Built and deployed automatically by the Docker Compose stack.
See `deploy/compose/docker-compose.yml` for service configuration.
