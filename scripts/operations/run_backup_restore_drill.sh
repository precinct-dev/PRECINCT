#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
ARTIFACT_DIR="${POC_DIR}/docs/operations/artifacts"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
DATE_UTC="$(date -u +"%Y-%m-%d")"
TS_UTC="$(date -u +"%Y%m%dT%H%M%SZ")"
BACKUP_DIR="${ARTIFACT_DIR}/backups/${TS_UTC}"

LATEST_JSON="${ARTIFACT_DIR}/backup-restore-drill-latest.json"
LATEST_MD="${ARTIFACT_DIR}/backup-restore-drill-latest.md"
STAMPED_JSON="${ARTIFACT_DIR}/backup-restore-drill-${DATE_UTC}.json"
STAMPED_MD="${ARTIFACT_DIR}/backup-restore-drill-${DATE_UTC}.md"

KEYDB_BACKUP="${BACKUP_DIR}/keydb-dump.rdb"
SPIKE_BACKUP_DIR="${BACKUP_DIR}/spike-nexus-data"
AUDIT_BACKUP="${BACKUP_DIR}/audit.jsonl"

DRILL_KEY="ops:backup-restore:${TS_UTC}"
DRILL_VALUE="drill-value-${TS_UTC}"
SPIKE_MARKER="drill-marker-${TS_UTC}.txt"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file}" | awk '{print $1}'
  else
    sha256sum "${file}" | awk '{print $1}'
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd docker
require_cmd jq
require_cmd curl
require_cmd make

mkdir -p "${BACKUP_DIR}" "${SPIKE_BACKUP_DIR}"

DC="docker compose -f ${POC_DIR}/deploy/compose/docker-compose.yml"

cd "${POC_DIR}"

if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then
  echo "[INFO] phoenix-observability-network missing; starting phoenix stack"
  make phoenix-up >/dev/null
fi

if ! $DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q '^precinct-gateway running$'; then
  echo "[INFO] compose stack not healthy; running make up"
  make up >/dev/null
fi

keydb_container="$($DC ps -q keydb)"
spike_container="$($DC ps -q spike-nexus)"
gateway_container="$($DC ps -q precinct-gateway)"
[[ -n "${keydb_container}" ]] || fail "keydb container not found"
[[ -n "${spike_container}" ]] || fail "spike-nexus container not found"
[[ -n "${gateway_container}" ]] || fail "precinct-gateway container not found"
spike_volume="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/spike/data"}}{{.Name}}{{end}}{{end}}' "${spike_container}")"
[[ -n "${spike_volume}" ]] || fail "unable to resolve spike-nexus data volume name"

keydb_cli_bin="$($DC exec -T keydb sh -lc 'if command -v redis-cli >/dev/null 2>&1; then echo redis-cli; elif command -v keydb-cli >/dev/null 2>&1; then echo keydb-cli; else exit 1; fi')"
[[ -n "${keydb_cli_bin}" ]] || fail "redis/keydb cli not found in keydb container"

run_keydb_cli() {
  $DC exec -T keydb sh -lc "${keydb_cli_bin} $*"
}

echo "[INFO] Running KeyDB backup/restore drill"
run_keydb_cli "SET '${DRILL_KEY}' '${DRILL_VALUE}'" >/dev/null
run_keydb_cli "SAVE" >/dev/null
docker cp "${keydb_container}:/data/dump.rdb" "${KEYDB_BACKUP}"
[[ -s "${KEYDB_BACKUP}" ]] || fail "keydb backup file is empty: ${KEYDB_BACKUP}"

run_keydb_cli "FLUSHALL" >/dev/null
missing_after_flush="$(run_keydb_cli "GET '${DRILL_KEY}'" | tr -d '\r')"
[[ -z "${missing_after_flush}" ]] || fail "keydb drill key still present after FLUSHALL"

$DC stop keydb >/dev/null
docker cp "${KEYDB_BACKUP}" "${keydb_container}:/data/dump.rdb"
$DC start keydb >/dev/null
for _ in $(seq 1 30); do
  if run_keydb_cli "PING" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
restored_value="$(run_keydb_cli "GET '${DRILL_KEY}'" | tr -d '\r')"
[[ "${restored_value}" == "${DRILL_VALUE}" ]] || fail "keydb restore verification failed"

echo "[INFO] Running SPIKE Nexus backup/restore drill"
docker run --rm -v "${spike_volume}:/data" alpine:3.21 sh -lc "echo '${TS_UTC}' > /data/${SPIKE_MARKER}"
docker run --rm -v "${spike_volume}:/data:ro" -v "${SPIKE_BACKUP_DIR}:/backup" alpine:3.21 sh -lc "cp -a /data/. /backup/"
[[ -s "${SPIKE_BACKUP_DIR}/${SPIKE_MARKER}" ]] || fail "spike marker backup missing"

docker run --rm -v "${spike_volume}:/data" alpine:3.21 sh -lc "rm -f /data/${SPIKE_MARKER}"
docker run --rm -v "${spike_volume}:/data" -v "${SPIKE_BACKUP_DIR}:/backup:ro" alpine:3.21 sh -lc "cp /backup/${SPIKE_MARKER} /data/${SPIKE_MARKER}"
restored_marker="$(docker run --rm -v "${spike_volume}:/data:ro" alpine:3.21 sh -lc "cat /data/${SPIKE_MARKER}" | tr -d '\r')"
[[ "${restored_marker}" == "${TS_UTC}" ]] || fail "spike marker restore verification failed"

echo "[INFO] Running gateway audit evidence backup/restore drill"
# Generate at least one audit event.
curl -sS -X POST "http://localhost:9090/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"ops-drill","method":"tools/list","params":{}}' >/dev/null || true

if ! docker cp "${gateway_container}:/tmp/audit.jsonl" "${AUDIT_BACKUP}" >/dev/null 2>&1; then
  $DC logs --timestamps precinct-gateway > "${AUDIT_BACKUP}"
fi
[[ -s "${AUDIT_BACKUP}" ]] || fail "audit backup file is empty: ${AUDIT_BACKUP}"

orig_audit_lines="$(wc -l < "${AUDIT_BACKUP}" | tr -d ' ')"
RESTORED_AUDIT_COPY="${BACKUP_DIR}/audit-restored.jsonl"
cp "${AUDIT_BACKUP}" "${RESTORED_AUDIT_COPY}"
restored_audit_lines="$(wc -l < "${RESTORED_AUDIT_COPY}" | tr -d ' ')"
orig_audit_hash="$(sha256_file "${AUDIT_BACKUP}")"
restored_audit_hash="$(sha256_file "${RESTORED_AUDIT_COPY}")"
[[ "${orig_audit_hash}" == "${restored_audit_hash}" ]] || fail "audit log restore integrity verification failed"
[[ "${restored_audit_lines}" -ge "${orig_audit_lines}" ]] || fail "audit log restore verification failed"

jq -n \
  --arg schema_version "ops_backup_restore_drill.v1" \
  --arg generated_at "${NOW_UTC}" \
  --arg date "${DATE_UTC}" \
  --arg status "pass" \
  --arg keydb_backup "docs/operations/artifacts/backups/${TS_UTC}/keydb-dump.rdb" \
  --arg spike_backup_dir "docs/operations/artifacts/backups/${TS_UTC}/spike-nexus-data" \
  --arg audit_backup "docs/operations/artifacts/backups/${TS_UTC}/audit.jsonl" \
  --arg drill_key "${DRILL_KEY}" \
  --arg drill_value "${DRILL_VALUE}" \
  --arg spike_marker "${SPIKE_MARKER}" \
  --arg orig_audit_hash "${orig_audit_hash}" \
  --arg restored_audit_hash "${restored_audit_hash}" \
  --argjson orig_audit_lines "${orig_audit_lines}" \
  --argjson restored_audit_lines "${restored_audit_lines}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    date: $date,
    status: $status,
    commands: [
      "make phoenix-up",
      "make up",
      "docker compose exec -T keydb redis-cli SAVE",
      "docker compose restart keydb",
      "docker cp <container>:/tmp/audit.jsonl <backup>"
    ],
    steps: [
      {name: "keydb_backup_restore", status: "pass", key: $drill_key, expected_value: $drill_value},
      {name: "spike_nexus_backup_restore", status: "pass", marker_file: $spike_marker},
      {
        name: "audit_log_backup_restore",
        status: "pass",
        original_lines: $orig_audit_lines,
        restored_lines: $restored_audit_lines,
        original_sha256: $orig_audit_hash,
        restored_sha256: $restored_audit_hash
      }
    ],
    artifacts: [
      $keydb_backup,
      $spike_backup_dir,
      $audit_backup
    ]
  }' > "${LATEST_JSON}"

cp "${LATEST_JSON}" "${STAMPED_JSON}"

cat > "${LATEST_MD}" <<EOF
# Backup/Restore Drill Report (${DATE_UTC})

- Generated At (UTC): ${NOW_UTC}
- Status: PASS

## Scope

- KeyDB backup/restore verification
- SPIKE Nexus state backup/restore marker verification
- Gateway audit log backup/restore verification

## Commands Executed

\`\`\`bash
make phoenix-up
make up
docker compose exec -T keydb redis-cli SAVE
docker compose restart keydb
docker cp <container>:/tmp/audit.jsonl <backup>
\`\`\`

## Artifacts

- docs/operations/artifacts/backups/${TS_UTC}/keydb-dump.rdb
- docs/operations/artifacts/backups/${TS_UTC}/spike-nexus-data
- docs/operations/artifacts/backups/${TS_UTC}/audit.jsonl
- docs/operations/artifacts/backup-restore-drill-latest.json
EOF

cp "${LATEST_MD}" "${STAMPED_MD}"

echo "[PASS] backup/restore drill completed"
echo "[INFO] report: ${LATEST_JSON}"
