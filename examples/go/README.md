# Go E2E Demo

Exercises every PRECINCT gateway middleware layer using the Go SDK.
This is the Go half of the `make demo-compose` suite (21 tests).

## What it tests

All 13 middleware layers with real requests through the full stack:
size guard, shape validation, SPIFFE auth, audit, tool registry, OPA policy,
DLP scanning, session context, step-up gating, deep scan, rate limiting,
circuit breaker, and token substitution.

## Usage

Normally run via Docker Compose (`make demo-compose`). To run locally:

```bash
go build -o demo .
./demo --gateway http://localhost:9090
```

Requires the full PRECINCT stack to be running (`make up`).
