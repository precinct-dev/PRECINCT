#!/usr/bin/env bash
set -euo pipefail

OS_URL="${OPENSEARCH_URL:-http://localhost:9200}"
DASH_URL="${OPENSEARCH_DASHBOARDS_URL:-http://localhost:5601}"

log() { printf '[opensearch-validate] %s\n' "$*"; }
fail() { printf '[opensearch-validate] ERROR: %s\n' "$*"; exit 1; }

curl -fsS "${OS_URL}/_cluster/health" >/dev/null || fail "OpenSearch health endpoint unavailable"
curl -fsS "${DASH_URL}/api/status" >/dev/null || fail "OpenSearch Dashboards status endpoint unavailable"

template_status="$(curl -s -o /dev/null -w '%{http_code}' "${OS_URL}/_index_template/precinct-audit-template")"
if [ "$template_status" != "200" ]; then
  fail "precinct-audit-template missing (HTTP ${template_status}); run make opensearch-seed"
fi

indices_json="$(curl -fsS "${OS_URL}/_cat/indices/precinct-audit-*?format=json" || echo '[]')"
index_count="$(printf '%s' "$indices_json" | jq 'length' 2>/dev/null || echo 0)"

if [ "$index_count" -eq 0 ]; then
  log "No precinct-audit indices yet (this is expected until gateway writes audit events in OpenSearch mode)."
else
  docs_total="$(printf '%s' "$indices_json" | jq '[.[]."docs.count" | tonumber] | add // 0' 2>/dev/null || echo 0)"
  log "Found ${index_count} precinct-audit index(es), total docs=${docs_total}."
fi

log "OpenSearch observability stack validation passed"
