#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
DASH_URL="${OPENSEARCH_DASHBOARDS_URL:-http://localhost:5601}"
ASSET_PATH="${ASSET_PATH:-config/opensearch-dashboards/precinct-audit-overview.ndjson}"

log() { printf '[opensearch-seed] %s\n' "$*"; }

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="${3:-60}"
  local sleep_s="${4:-2}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_s"
  done

  log "ERROR: timed out waiting for ${name} at ${url}"
  return 1
}

log "Waiting for OpenSearch"
wait_http_ok "${OS_URL}/_cluster/health" "OpenSearch"

log "Waiting for OpenSearch Dashboards"
wait_http_ok "${DASH_URL}/api/status" "OpenSearch Dashboards"

log "Creating index template precinct-audit-template"
curl -fsS -X PUT "${OS_URL}/_index_template/precinct-audit-template" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["precinct-audit-*"] ,
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "dynamic": true,
        "properties": {
          "timestamp": {"type": "date"},
          "@timestamp": {"type": "date"},
          "decision_id": {"type": "keyword"},
          "trace_id": {"type": "keyword"},
          "session_id": {"type": "keyword"},
          "spiffe_id": {"type": "keyword"},
          "result": {"type": "keyword"},
          "status_code": {"type": "integer"},
          "middleware": {"type": "keyword"},
          "path": {"type": "keyword"},
          "method": {"type": "keyword"},
          "security.signal_keys": {"type": "keyword"}
        }
      }
    }
  }' >/dev/null

if [ ! -f "$ASSET_PATH" ]; then
  log "ERROR: dashboard asset not found: $ASSET_PATH"
  exit 1
fi

log "Importing saved objects from ${ASSET_PATH}"
curl -fsS -X POST "${DASH_URL}/api/saved_objects/_import?overwrite=true" \
  -H 'osd-xsrf: true' \
  -H 'securitytenant: global' \
  -F "file=@${ASSET_PATH}" >/dev/null

log "Seed complete"
log "Dashboards UI: ${DASH_URL}/app/dashboards"
