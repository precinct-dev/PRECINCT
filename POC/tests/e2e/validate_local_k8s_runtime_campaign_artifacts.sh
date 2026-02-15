#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ARTIFACT_JSON="${POC_ROOT}/docs/security/artifacts/local-k8s-runtime-campaign-latest.json"
ARTIFACT_MD="${POC_ROOT}/docs/security/local-k8s-runtime-campaign-latest.md"
RUNTIME_REPORT="${POC_ROOT}/build/validation/k8s-runtime-validation-report.v2.4.json"

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
[ -f "${RUNTIME_REPORT}" ] || fail "missing runtime report: ${RUNTIME_REPORT}"

status="$(jq -r '.summary.status // empty' "${ARTIFACT_JSON}")"
[ "${status}" = "pass" ] || fail "campaign summary status must be pass"

checks_total="$(jq -r '.summary.checks_total // -1' "${ARTIFACT_JSON}")"
checks_passed="$(jq -r '.summary.checks_passed // -1' "${ARTIFACT_JSON}")"
[ "${checks_total}" = "${checks_passed}" ] || fail "checks_passed must equal checks_total"

context="$(jq -r '.environment.cluster_context // empty' "${ARTIFACT_JSON}")"
[ "${context}" = "docker-desktop" ] || fail "cluster context must be docker-desktop"

pass "Local K8s runtime campaign artifacts validated"
