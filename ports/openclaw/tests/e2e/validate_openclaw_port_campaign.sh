#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)}"
ARTIFACT_DIR="${POC_DIR}/tests/e2e/artifacts"
STAMP="${OPENCLAW_CAMPAIGN_DATE:-2026-02-21}"
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
  "openclaw_port_unit_suite" \
  "go test ./ports/openclaw/... -count=1"

run_check \
  "openclaw_e2e_walking_skeleton" \
  "bash ports/openclaw/tests/e2e/scenario_j_openclaw_walking_skeleton.sh"

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
