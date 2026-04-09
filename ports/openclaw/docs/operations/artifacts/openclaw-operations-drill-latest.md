# OpenClaw Operations Drill Report (2026-03-31)

- Generated At (UTC): 2026-03-31T09:41:17Z
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
docker compose restart precinct-gateway
make compose-production-intent-preflight
go run ./cmd/openclaw-ws-smoke --phase post-restart
```

## Artifacts

- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-incident.json
- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-recovery.json
- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-gateway.log
- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-preflight.log
- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-ws-pre-restart.json
- docs/operations/artifacts/openclaw-operations-drill-20260331T094117Z-ws-post-restart.json
- docs/operations/artifacts/openclaw-operations-drill-latest.json
