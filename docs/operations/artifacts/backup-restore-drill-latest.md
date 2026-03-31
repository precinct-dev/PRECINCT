# Backup/Restore Drill Report (2026-03-31)

- Generated At (UTC): 2026-03-31T09:38:23Z
- Status: PASS

## Scope

- KeyDB backup/restore verification
- SPIKE Nexus state backup/restore marker verification
- Gateway audit log backup/restore verification

## Commands Executed

```bash
make phoenix-up
make up
docker compose exec -T keydb redis-cli SAVE
docker compose restart keydb
docker cp <container>:/tmp/audit.jsonl <backup>
```

## Artifacts

- docs/operations/artifacts/backups/20260331T093823Z/keydb-dump.rdb
- docs/operations/artifacts/backups/20260331T093823Z/spike-nexus-data
- docs/operations/artifacts/backups/20260331T093823Z/audit.jsonl
- docs/operations/artifacts/backup-restore-drill-latest.json
