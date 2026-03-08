---
id: oc-sdh
title: "Validate OpenClaw integration in Docker Compose mode"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:58:20Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:9a914a8ad0b2818c1fbf233ad9de016f28409831f23b6d481c8f7f7913e88e3e"
closed_at: 2026-02-21T20:15:52Z
close_reason: "make demo-compose exits 0. ALL DEMOS PASSED (compose). Full 28-test E2E suite, clean teardown."
blocks: [oc-ht7]
parent: oc-6bq
blocked_by: [oc-b9w]
follows: [oc-b9w]
led_to: [oc-ht7]
---

## Description
## User Story

As a gateway operator, I need to confirm the OpenClaw integration works correctly in Docker Compose mode, so that the containerized deployment path is validated against the updated upstream contract.

## Context and Business Value

The Docker Compose stack (`docker-compose.yml`) provides the primary local development and CI deployment mode for the MCP Security Gateway. The gateway runs containerized with SPIRE for identity, OPA for policy, and the full 13-layer middleware chain. OpenClaw connects as an external HTTP/WS client through this stack.

The pack config at `packs/openclaw/pack.v1.json` specifies:
```json
"runtime_profile_hints": {
    "compose": {
        "strict_deepscan": true,
        "preferred_validation": ["make demo-compose"]
    }
}
```

The `make demo-compose` target runs `bash demo/run.sh compose` which exercises the full stack. This story validates that:
1. The gateway starts correctly in Docker Compose
2. OpenClaw HTTP endpoints (`/v1/responses`, `/tools/invoke`) are reachable through the containerized gateway
3. OpenClaw WS endpoint (`/openclaw/ws`) accepts connections through the containerized gateway
4. The updated device-identity enforcement for node-role connections works in the containerized environment
5. Audit chain captures all decisions

## Implementation

### Step 1: Start the Docker Compose stack

```bash
cd /Users/ramirosalas/workspace/agentic_reference_architecture/POC
make up
```
Wait for all services to be healthy.

### Step 2: Run demo-compose

```bash
make demo-compose
```
This exercises the full E2E demo path. If it fails, diagnose and fix.

### Step 3: Manual validation probes (if demo script does not cover OpenClaw paths)

If `demo/run.sh compose` does not explicitly hit OpenClaw endpoints, add manual curl probes:

```bash
# HTTP: /v1/responses (should get policy response, even without real model provider)

curl -s -X POST http://localhost:8443/v1/responses \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{"model":"llama-3.3-70b-versatile","input":"test"}' \

  | jq .

# HTTP: /tools/invoke (safe tool)

curl -s -X POST http://localhost:8443/tools/invoke \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{"tool":"read","args":{"path":"/tmp/demo.txt"}}' \

  | jq .

# WS: smoke test

go run ./cmd/openclaw-ws-smoke --gateway-url ws://localhost:8443/openclaw/ws
```

### Step 4: Verify strict deepscan mode

```bash
make demo-compose-strict-observability
```
This exercises the strict observability overlay. OpenClaw endpoints should still work.

### Step 5: Tear down

```bash
make down
```

## Acceptance Criteria

1. [AC1] `make up` starts all required services (gateway, spire-server, spire-agent, etc.) and they report healthy.
2. [AC2] `make demo-compose` exits with status 0.
3. [AC3] HTTP POST to `/v1/responses` through the containerized gateway returns a valid JSON response (200 or policy-controlled error with correct envelope shape).
4. [AC4] HTTP POST to `/tools/invoke` with a safe tool returns `ok: true`.
5. [AC5] WS connection to `/openclaw/ws` with SPIFFE identity succeeds and responds to connect + health frames.
6. [AC6] `make down` cleanly tears down the stack.

## Testing Requirements
### Unit tests (mocks OK)

- No new unit tests -- this is a deployment validation story.

### Integration tests (MANDATORY, no mocks)

- The Docker Compose validation IS the integration test. Evidence is:
  - `make demo-compose` exit status 0
  - curl probe outputs showing correct response shapes
  - WS smoke test output

### Test commands

```bash
make up
make demo-compose
make demo-compose-strict-observability
make down
```

## Scope Boundary

Scope: Deployment validation only. Files potentially modified:
- `demo/run.sh` -- if OpenClaw-specific probes need to be added
- `docker-compose.yml` -- only if a configuration issue is found (unlikely)
No changes to: adapter code, core gateway, middleware, policy engine, Go tests.

## Dependencies

Depends on Story oc-b9w (port validation campaign passes) being complete, which in turn depends on oc-a39 and oc-0bl.

MANDATORY SKILLS TO REVIEW:
- None identified. Docker Compose, shell scripting. No specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocked_by oc-b9w

## Links
- Parent: [[oc-6bq]]
- Blocks: [[oc-ht7]]
- Blocked by: [[oc-b9w]]
- Follows: [[oc-b9w]]
- Led to: [[oc-ht7]]

## Comments
