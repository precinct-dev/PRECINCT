#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
ARTIFACT_DIR="${POC_DIR}/docs/operations/artifacts"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
DATE_UTC="$(date -u +"%Y-%m-%d")"
TS_UTC="$(date -u +"%Y%m%dT%H%M%SZ")"

LATEST_JSON="${ARTIFACT_DIR}/openclaw-operations-drill-latest.json"
LATEST_MD="${ARTIFACT_DIR}/openclaw-operations-drill-latest.md"
STAMPED_JSON="${ARTIFACT_DIR}/openclaw-operations-drill-${DATE_UTC}.json"
STAMPED_MD="${ARTIFACT_DIR}/openclaw-operations-drill-${DATE_UTC}.md"

INCIDENT_BODY="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-incident.json"
RECOVERY_BODY="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-recovery.json"
GATEWAY_LOG="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-gateway.log"
PREFLIGHT_LOG="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-preflight.log"
WS_PRE_RESTART_BODY="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-ws-pre-restart.json"
WS_POST_RESTART_BODY="${ARTIFACT_DIR}/openclaw-operations-drill-${TS_UTC}-ws-post-restart.json"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

check_gateway_health() {
  local endpoint="http://localhost:9090/health"
  for _ in $(seq 1 30); do
    if curl -sSf "${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

run_ws_smoke_probe() {
  local phase="$1"
  local output_file="$2"

  if ! go run ./cmd/openclaw-ws-smoke \
    --url "ws://localhost:9090/openclaw/ws" \
    --spiffe-id "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
    --phase "${phase}" \
    --output "${output_file}" >/dev/null; then
    fail "OpenClaw WS smoke probe failed for phase ${phase}; see ${output_file}"
  fi

  local probe_status
  probe_status="$(jq -r '.status // empty' "${output_file}")"
  [[ "${probe_status}" == "pass" ]] || fail "OpenClaw WS smoke probe status != pass for phase ${phase}"

  local health_status
  health_status="$(jq -r '.health_response.payload.status // empty' "${output_file}")"
  [[ "${health_status}" == "ok" ]] || fail "OpenClaw WS smoke probe health status != ok for phase ${phase}"
}

require_cmd docker
require_cmd jq
require_cmd curl
require_cmd make
require_cmd go

DC="docker compose -f ${POC_DIR}/deploy/compose/docker-compose.yml"

mkdir -p "${ARTIFACT_DIR}"
cd "${POC_DIR}"

if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then
  make phoenix-up >/dev/null
fi

if ! $DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -q '^precinct-gateway running$'; then
  make up >/dev/null
fi

check_gateway_health || fail "gateway did not become healthy before drill"
run_ws_smoke_probe "pre-restart" "${WS_PRE_RESTART_BODY}"

incident_code="$(curl -sS -o "${INCIDENT_BODY}" -w '%{http_code}' \
  -X POST "http://localhost:9090/tools/invoke" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{"tool":"sessions_send","args":{"message":"openclaw-incident-drill"}}')"

[[ "${incident_code}" == "403" ]] || fail "incident simulation expected HTTP 403, got ${incident_code}"
incident_reason="$(jq -r '.reason_code // .error.reason_code // empty' "${INCIDENT_BODY}")"
[[ -n "${incident_reason}" ]] || fail "incident simulation response missing reason_code"

$DC logs --timestamps --tail 300 precinct-gateway > "${GATEWAY_LOG}"
[[ -s "${GATEWAY_LOG}" ]] || fail "gateway log capture is empty"

$DC restart precinct-gateway >/dev/null
check_gateway_health || fail "gateway did not recover after restart containment"

if ! make compose-production-intent-preflight > "${PREFLIGHT_LOG}" 2>&1; then
  fail "compose-production-intent-preflight failed; see ${PREFLIGHT_LOG}"
fi

recovery_code="$(curl -sS -o "${RECOVERY_BODY}" -w '%{http_code}' \
  -X POST "http://localhost:9090/tools/invoke" \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{"tool":"sessions_send","args":{"message":"openclaw-recovery-check"}}')"

[[ "${recovery_code}" == "403" ]] || fail "post-recovery deny check expected HTTP 403, got ${recovery_code}"
recovery_reason="$(jq -r '.reason_code // .error.reason_code // empty' "${RECOVERY_BODY}")"
[[ -n "${recovery_reason}" ]] || fail "post-recovery response missing reason_code"
run_ws_smoke_probe "post-restart" "${WS_POST_RESTART_BODY}"

jq -n \
  --arg schema_version "openclaw_ops_drill.v1" \
  --arg generated_at "${NOW_UTC}" \
  --arg date "${DATE_UTC}" \
  --arg status "pass" \
  --arg incident_code "${incident_code}" \
  --arg incident_reason "${incident_reason}" \
  --arg recovery_code "${recovery_code}" \
  --arg recovery_reason "${recovery_reason}" \
  --arg incident_body "docs/operations/artifacts/$(basename "${INCIDENT_BODY}")" \
  --arg recovery_body "docs/operations/artifacts/$(basename "${RECOVERY_BODY}")" \
  --arg gateway_log "docs/operations/artifacts/$(basename "${GATEWAY_LOG}")" \
  --arg preflight_log "docs/operations/artifacts/$(basename "${PREFLIGHT_LOG}")" \
  --arg ws_pre_restart "docs/operations/artifacts/$(basename "${WS_PRE_RESTART_BODY}")" \
  --arg ws_post_restart "docs/operations/artifacts/$(basename "${WS_POST_RESTART_BODY}")" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    date: $date,
    status: $status,
    commands: [
      "make phoenix-up",
      "make up",
      "go run ./cmd/openclaw-ws-smoke --phase pre-restart",
      "curl -X POST http://localhost:9090/tools/invoke (sessions_send incident probe)",
      "docker compose restart precinct-gateway",
      "make compose-production-intent-preflight",
      "go run ./cmd/openclaw-ws-smoke --phase post-restart"
    ],
    steps: [
      {
        name: "stack_readiness",
        status: "pass",
        evidence: "gateway health endpoint returned 200 before drill"
      },
      {
        name: "ws_probe_pre_restart",
        status: "pass",
        artifact: $ws_pre_restart
      },
      {
        name: "incident_trigger_deny",
        status: "pass",
        http_code: ($incident_code | tonumber),
        reason_code: $incident_reason
      },
      {
        name: "log_capture",
        status: "pass",
        artifact: $gateway_log
      },
      {
        name: "containment_restart",
        status: "pass",
        evidence: "gateway restarted and returned healthy state"
      },
      {
        name: "rollback_preflight",
        status: "pass",
        artifact: $preflight_log
      },
      {
        name: "post_recovery_deny_check",
        status: "pass",
        http_code: ($recovery_code | tonumber),
        reason_code: $recovery_reason
      },
      {
        name: "ws_probe_post_restart",
        status: "pass",
        artifact: $ws_post_restart
      }
    ],
    artifacts: [
      $incident_body,
      $recovery_body,
      $gateway_log,
      $preflight_log,
      $ws_pre_restart,
      $ws_post_restart
    ]
  }' > "${LATEST_JSON}"

cp "${LATEST_JSON}" "${STAMPED_JSON}"

cat > "${LATEST_MD}" <<EOF
# OpenClaw Operations Drill Report (${DATE_UTC})

- Generated At (UTC): ${NOW_UTC}
- Status: PASS

## Drill Scope

- Incident simulation on OpenClaw HTTP wrapper path /tools/invoke
- Live OpenClaw WS control-plane smoke probe before restart
- Gateway containment restart
- Rollback preflight validation
- Post-recovery deny-path verification
- Live OpenClaw WS control-plane smoke probe after restart

## Commands Executed

\`\`\`bash
make phoenix-up
make up
go run ./cmd/openclaw-ws-smoke --phase pre-restart
curl -X POST http://localhost:9090/tools/invoke ...
docker compose restart precinct-gateway
make compose-production-intent-preflight
go run ./cmd/openclaw-ws-smoke --phase post-restart
\`\`\`

## Artifacts

- docs/operations/artifacts/$(basename "${INCIDENT_BODY}")
- docs/operations/artifacts/$(basename "${RECOVERY_BODY}")
- docs/operations/artifacts/$(basename "${GATEWAY_LOG}")
- docs/operations/artifacts/$(basename "${PREFLIGHT_LOG}")
- docs/operations/artifacts/$(basename "${WS_PRE_RESTART_BODY}")
- docs/operations/artifacts/$(basename "${WS_POST_RESTART_BODY}")
- docs/operations/artifacts/openclaw-operations-drill-latest.json
EOF

cp "${LATEST_MD}" "${STAMPED_MD}"

echo "[PASS] OpenClaw incident/rollback drill completed"
echo "[INFO] report: ${LATEST_JSON}"
