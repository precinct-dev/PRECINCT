# Backup/Restore Drill Report (2026-03-15)

- Generated At (UTC): 2026-03-15T03:56:28Z
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

- docs/operations/artifacts/backups/20260315T035628Z/keydb-dump.rdb
- docs/operations/artifacts/backups/20260315T035628Z/spike-nexus-data
- docs/operations/artifacts/backups/20260315T035628Z/audit.jsonl
- docs/operations/artifacts/backup-restore-drill-latest.json
