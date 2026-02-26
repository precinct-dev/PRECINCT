# OpenClaw Operations Drill Report (2026-02-21)

- Generated At (UTC): 2026-02-21T20:09:15Z
- Status: PASS

## Drill Scope

- Incident simulation on OpenClaw HTTP wrapper path /tools/invoke
- Live OpenClaw WS control-plane smoke probe before restart
- Gateway containment restart
- Rollback preflight validation
- Post-recovery deny-path verification
- Live OpenClaw WS control-plane smoke probe after restart

## Commands Executed

```bash
make phoenix-up
make up
go run ./cmd/openclaw-ws-smoke --phase pre-restart
curl -X POST http://localhost:9090/tools/invoke ...
docker compose restart mcp-security-gateway
make compose-production-intent-preflight
go run ./cmd/openclaw-ws-smoke --phase post-restart
```

## Artifacts

- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-incident.json
- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-recovery.json
- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-gateway.log
- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-preflight.log
- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-ws-pre-restart.json
- docs/operations/artifacts/openclaw-operations-drill-20260221T200915Z-ws-post-restart.json
- docs/operations/artifacts/openclaw-operations-drill-latest.json
