#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
ARTIFACT_DIR="${POC_DIR}/tests/e2e/artifacts"
STAMP="${OPENCLAW_CAMPAIGN_DATE:-2026-02-16}"
LOG_PATH="${ARTIFACT_DIR}/openclaw-port-campaign-${STAMP}.log"
JSON_PATH="${ARTIFACT_DIR}/openclaw-port-campaign-${STAMP}.json"
RESULTS_TSV="$(mktemp)"

mkdir -p "${ARTIFACT_DIR}"
: > "${LOG_PATH}"

run_check() {
  local name="$1"
  local cmd="$2"
  local start_ts end_ts duration status

  start_ts="$(date +%s)"
  {
    echo "=== ${name} ==="
    echo "CMD: ${cmd}"
  } >> "${LOG_PATH}"

  if bash -lc "${cmd}" >> "${LOG_PATH}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi

  end_ts="$(date +%s)"
  duration="$((end_ts - start_ts))"

  printf '%s\t%s\t%s\t%s\n' "${name}" "${status}" "${duration}" "${cmd}" >> "${RESULTS_TSV}"
  printf '[%s] %s (%ss)\n' "${status^^}" "${name}" "${duration}"
}

cd "${POC_DIR}"

run_check \
  "required_integration_suite" \
  "go test ./tests/integration/... -run 'OpenClaw|Security|Adversarial' -count=1"

run_check \
  "openclaw_gateway_unit_suite" \
  "go test ./internal/gateway/... -run 'OpenClaw' -count=1"

run_check \
  "openclaw_parser_unit_suite" \
  "go test ./internal/integrations/openclaw/... -count=1"

run_check \
  "openclaw_integration_authz_audit_suite" \
  "go test ./tests/integration/... -run 'GatewayAuthz_OpenClawWSDenyMatrix|AuditOpenClawWSCorrelation' -count=1"

jq -Rn \
  --arg campaign_id "openclaw-port-validation-${STAMP}" \
  --arg executed_at "$(date -u +%FT%TZ)" \
  --arg log_path "${LOG_PATH}" \
  --rawfile rows "${RESULTS_TSV}" '
    ($rows | split("\n") | map(select(length > 0) | split("\t"))) as $r
    | {
        campaign_id: $campaign_id,
        executed_at: $executed_at,
        log_path: $log_path,
        checks: [
          $r[] | {
            name: .[0],
            status: .[1],
            duration_seconds: (.[2] | tonumber),
            command: .[3]
          }
        ],
        summary: {
          total: ($r | length),
          pass: ([ $r[] | select(.[1] == "pass") ] | length),
          fail: ([ $r[] | select(.[1] == "fail") ] | length)
        }
      }
  ' > "${JSON_PATH}"

rm -f "${RESULTS_TSV}"

echo
echo "Campaign log: ${LOG_PATH}"
echo "Campaign JSON: ${JSON_PATH}"

fail_count="$(jq -r '.summary.fail' "${JSON_PATH}")"
if [[ "${fail_count}" != "0" ]]; then
  exit 1
fi
