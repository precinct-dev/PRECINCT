#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
GATE_SCRIPT="${POC_DIR}/scripts/observability/validate_observability_gate.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

[[ -x "${GATE_SCRIPT}" ]] || fail "gate script missing or not executable: ${GATE_SCRIPT}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

audit_file="${tmp_dir}/audit.log"
trace_file="${tmp_dir}/trace.log"
echo "{\"event\":\"audit\"}" > "${audit_file}"
echo "{\"event\":\"trace\"}" > "${trace_file}"

echo "[INFO] Scenario 1: strict mode with telemetry sinks down (expect fail)"
make -C "${POC_DIR}" phoenix-down >/dev/null 2>&1 || true
if "${GATE_SCRIPT}" --strict --audit-file "${audit_file}" --trace-file "${trace_file}" >/tmp/obs-gate-strict-down.log 2>&1; then
  cat /tmp/obs-gate-strict-down.log
  fail "strict observability gate unexpectedly passed with sinks down"
fi
if ! rg -n "required telemetry sinks unavailable" /tmp/obs-gate-strict-down.log >/dev/null 2>&1; then
  cat /tmp/obs-gate-strict-down.log
  fail "strict observability failure reason was not explicit"
fi

echo "[INFO] Scenario 2: non-strict mode with telemetry sinks down (expect pass + warning)"
if ! "${GATE_SCRIPT}" --audit-file "${audit_file}" --trace-file "${trace_file}" >/tmp/obs-gate-nonstrict-down.log 2>&1; then
  cat /tmp/obs-gate-nonstrict-down.log
  fail "non-strict observability gate should pass when sinks are down"
fi
if ! rg -n "non-strict mode allows campaign to continue" /tmp/obs-gate-nonstrict-down.log >/dev/null 2>&1; then
  cat /tmp/obs-gate-nonstrict-down.log
  fail "non-strict warning message missing"
fi

echo "[INFO] Scenario 3: strict mode with telemetry sinks up (expect pass)"
make -C "${POC_DIR}" phoenix-up >/dev/null
if ! "${GATE_SCRIPT}" --strict --audit-file "${audit_file}" --trace-file "${trace_file}" >/tmp/obs-gate-strict-up.log 2>&1; then
  cat /tmp/obs-gate-strict-up.log
  fail "strict observability gate should pass with sinks up and evidence files present"
fi

make -C "${POC_DIR}" phoenix-down >/dev/null 2>&1 || true

echo "[PASS] Observability evidence gate validation passed"
