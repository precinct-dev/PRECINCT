# Python E2E Demo

Exercises every PRECINCT gateway middleware layer using the Python SDK.
This is the Python half of the `make demo-compose` suite (22 tests).

## What it tests

All 13 middleware layers with real requests through the full stack,
mirroring the Go demo with Python SDK calls.

## Usage

Normally run via Docker Compose (`make demo-compose`). To run locally:

```bash
uv run python demo.py --gateway http://localhost:9090
```

Requires the full PRECINCT stack to be running (`make up`).
