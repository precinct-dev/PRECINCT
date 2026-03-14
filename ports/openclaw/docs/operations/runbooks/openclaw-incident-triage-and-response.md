# OpenClaw Incident Triage and Response Runbook

Last Updated: 2026-02-16  
Scope: OpenClaw secure-port wrapper lanes (`/v1/responses`, `/tools/invoke`, `/openclaw/ws`) mediated by `mcp-security-gateway`.

## 1. Trigger Conditions

- Unexpected denial spikes on OpenClaw wrapper routes.
- Suspected auth bypass attempts on OpenClaw WS control plane.
- Dangerous tool invocation attempts through OpenClaw HTTP lane.
- Correlation/audit drift (missing `decision_id` or `trace_id` in incident timeline).

## 2. First 10 Minutes (Triage)

```bash
make phoenix-up
make up
curl -sf http://localhost:9090/health | jq .
docker compose logs --tail 200 mcp-security-gateway
curl -sS -X POST http://localhost:9090/tools/invoke \
  -H 'Content-Type: application/json' \
  -H 'X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev' \
  -d '{"tool":"sessions_send","args":{"message":"incident-probe"}}' | jq .
go run ./cmd/openclaw-ws-smoke \
  --url ws://localhost:9090/openclaw/ws \
  --spiffe-id spiffe://poc.local/agents/mcp-client/dspy-researcher/dev \
  --phase triage \
  --output docs/operations/artifacts/openclaw-ws-smoke-triage.json
go test ./tests/integration/... -run 'TestGatewayAuthz_OpenClawWSDenyMatrix_Integration' -count=1
```

## 3. Containment

```bash
# Isolate and restart wrapper ingress if behavior is inconsistent.
docker compose stop mcp-security-gateway
docker compose restart mcp-security-gateway

# Capture bounded incident evidence window.
mkdir -p docs/operations/artifacts
docker compose logs --timestamps --tail 400 mcp-security-gateway \
  > docs/operations/artifacts/openclaw-incident-gateway-$(date -u +%Y%m%dT%H%M%SZ).log
```

## 4. Recovery Validation

```bash
curl -sf http://localhost:9090/health | jq .
go run ./cmd/openclaw-ws-smoke \
  --url ws://localhost:9090/openclaw/ws \
  --spiffe-id spiffe://poc.local/agents/mcp-client/dspy-researcher/dev \
  --phase post-containment \
  --output docs/operations/artifacts/openclaw-ws-smoke-post-containment.json
bash tests/e2e/validate_openclaw_operations_runbook_pack.sh
make operations-readiness-validate
```

## 5. Escalation and Evidence

- Attach command transcript and artifacts in active `bd` story notes.
- Include failing reason code(s) and associated `decision_id`/`trace_id`.
- Create remediation bugs for any non-deterministic deny or recovery failure.
