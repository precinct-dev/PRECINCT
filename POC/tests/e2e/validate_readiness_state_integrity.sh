#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
SNAPSHOT_INPUT="${1:-docs/status/production-readiness-state.json}"

if [[ "${SNAPSHOT_INPUT}" = /* ]]; then
  SNAPSHOT_PATH="${SNAPSHOT_INPUT}"
else
  SNAPSHOT_PATH="${POC_DIR}/${SNAPSHOT_INPUT}"
fi

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

read_bd_field() {
  local issue_id="$1"
  local jq_expr="$2"
  bd show "${issue_id}" --json | jq -r "${jq_expr}"
}

require_cmd bd
require_cmd jq

[[ -f "${SNAPSHOT_PATH}" ]] || fail "snapshot file not found: ${SNAPSHOT_PATH}"

echo "[INFO] Validating readiness state snapshot: ${SNAPSHOT_PATH}"

story_count="$(jq '.story_states | length' "${SNAPSHOT_PATH}")"
[[ "${story_count}" -gt 0 ]] || fail "snapshot story_states must contain at least one story"

while IFS= read -r row; do
  id="$(jq -r '.id' <<<"${row}")"
  expected_status="$(jq -r '.expected_status' <<<"${row}")"
  expected_closed_on="$(jq -r '.expected_closed_on // empty' <<<"${row}")"

  actual_status="$(read_bd_field "${id}" '.[0].status // empty')"
  [[ -n "${actual_status}" ]] || fail "unable to read bd status for ${id}"

  if [[ "${actual_status}" != "${expected_status}" ]]; then
    fail "status drift for ${id}: expected ${expected_status}, got ${actual_status}"
  fi

  if [[ -n "${expected_closed_on}" ]]; then
    actual_closed_on="$(read_bd_field "${id}" '.[0].closed_at // empty' | cut -d'T' -f1)"
    if [[ -z "${actual_closed_on}" ]]; then
      fail "closed date missing for ${id}: expected ${expected_closed_on}"
    fi
    if [[ "${actual_closed_on}" != "${expected_closed_on}" ]]; then
      fail "closed date drift for ${id}: expected ${expected_closed_on}, got ${actual_closed_on}"
    fi
  fi

  echo "[PASS] ${id} status matches (${actual_status})"
done < <(jq -c '.story_states[]' "${SNAPSHOT_PATH}")

gate_type="$(jq -r '.external_app_full_port_gate | type' "${SNAPSHOT_PATH}")"
if [[ "${gate_type}" != "null" && "${gate_type}" != "" ]]; then
  gate_story_id="$(jq -r '.external_app_full_port_gate.story_id' "${SNAPSHOT_PATH}")"
  expected_gate_status="$(jq -r '.external_app_full_port_gate.expected_status' "${SNAPSHOT_PATH}")"
  required_blocker_story_id="$(jq -r '.external_app_full_port_gate.required_blocker_story_id' "${SNAPSHOT_PATH}")"

  actual_gate_status="$(read_bd_field "${gate_story_id}" '.[0].status // empty')"
  [[ -n "${actual_gate_status}" ]] || fail "unable to read bd status for ${gate_story_id}"

  if [[ "${actual_gate_status}" != "${expected_gate_status}" ]]; then
    fail "External-app full-port gate status drift for ${gate_story_id}: expected ${expected_gate_status}, got ${actual_gate_status}"
  fi

  dependency_present="$(bd show "${gate_story_id}" --json | jq -r --arg blocker "${required_blocker_story_id}" 'if ((.[0].dependencies // []) | map(select(.id == $blocker and .dependency_type == "blocks")) | length) > 0 then 1 else 0 end')"
  [[ "${dependency_present}" -eq 1 ]] || fail "External-app full-port story ${gate_story_id} is missing blocker dependency on ${required_blocker_story_id}"

  blocker_status="$(read_bd_field "${required_blocker_story_id}" '.[0].status // empty')"
  allowed_blocker_status_match="$(jq -r --arg status "${blocker_status}" '.external_app_full_port_gate.required_blocker_statuses | any(. == $status) | if . then 1 else 0 end' "${SNAPSHOT_PATH}")"
  if [[ "${allowed_blocker_status_match}" -ne 1 ]]; then
    fail "blocker story ${required_blocker_story_id} status ${blocker_status} is outside allowed gate statuses"
  fi

  echo "[PASS] External-app full-port gate story ${gate_story_id} matches expected status (${expected_gate_status}) with dependency linkage to ${required_blocker_story_id}"
else
  echo "[SKIP] No external_app_full_port_gate defined in snapshot"
fi

echo "[PASS] readiness state integrity validation passed"
