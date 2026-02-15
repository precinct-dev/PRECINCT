#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ARTIFACT_JSON="${POC_ROOT}/docs/security/artifacts/production-reality-closure-local-latest.json"
ARTIFACT_MD="${POC_ROOT}/docs/security/production-reality-closure-local-latest.md"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -f "${ARTIFACT_JSON}" ] || fail "missing artifact: ${ARTIFACT_JSON}"
[ -f "${ARTIFACT_MD}" ] || fail "missing artifact: ${ARTIFACT_MD}"

decision="$(jq -r '.go_no_go.decision // empty' "${ARTIFACT_JSON}")"
[ "${decision}" = "GO" ] || fail "go_no_go.decision must be GO"

checks_failed="$(jq -r '[.readiness_matrix[] | select(.result != "pass")] | length' "${ARTIFACT_JSON}")"
[ "${checks_failed}" = "0" ] || fail "all readiness_matrix checks must be pass"

for story in RFA-l6h6.8.1 RFA-l6h6.8.2 RFA-l6h6.8.3 RFA-l6h6.8.4 RFA-l6h6.8.5 RFA-l6h6.8.6 RFA-l6h6.8.7; do
  status="$(jq -r --arg s "${story}" '.blocker_statuses[$s] // empty' "${ARTIFACT_JSON}")"
  [ "${status}" = "closed" ] || fail "blocker ${story} must be closed in closure artifact"
done

pass "Production reality closure local artifacts validated"
