#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

DOC_PATH="${POC_DIR}/docs/operations/managed-cloud-bootstrap-prerequisites.md"
TEMPLATE_PATH="${POC_DIR}/docs/operations/artifacts/managed-cloud-bootstrap-handoff.template.json"
PREFLIGHT_SCRIPT="${POC_DIR}/scripts/operations/managed_cloud_bootstrap_preflight.sh"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  rg -n --pcre2 "${pattern}" "${file}" >/dev/null 2>&1 || fail "${message}"
}

require_cmd jq
require_cmd rg

[[ -f "${DOC_PATH}" ]] || fail "missing prerequisite contract doc: ${DOC_PATH}"
[[ -f "${TEMPLATE_PATH}" ]] || fail "missing handoff template: ${TEMPLATE_PATH}"
[[ -f "${PREFLIGHT_SCRIPT}" ]] || fail "missing managed-cloud preflight script: ${PREFLIGHT_SCRIPT}"
pass "managed-cloud prerequisite assets exist"

assert_contains "${DOC_PATH}" '^## Required Inputs' "doc missing Required Inputs section"
assert_contains "${DOC_PATH}" '^## Ownership Matrix' "doc missing Ownership Matrix section"
assert_contains "${DOC_PATH}" '^## Deterministic Preflight' "doc missing Deterministic Preflight section"
assert_contains "${DOC_PATH}" 'RFA-l6h6.8.5' "doc must reference runtime campaign consumption"
pass "managed-cloud contract doc includes required sections"

jq -e '.contract_version == "managed-cloud-bootstrap.v1"' "${TEMPLATE_PATH}" >/dev/null \
  || fail "handoff template contract_version mismatch"
jq -e '.cluster.name and .cluster.region and .cluster.kubernetes_version' "${TEMPLATE_PATH}" >/dev/null \
  || fail "handoff template missing cluster metadata keys"
jq -e '(.access.kube_context | length > 0) and (.access.credential_owner | length > 0) and (.required_namespaces | length > 0)' "${TEMPLATE_PATH}" >/dev/null \
  || fail "handoff template missing access/namespace requirements"
pass "handoff template structure is valid"

tmp_log="$(mktemp)"
set +e
env -i PATH="${PATH}" bash "${PREFLIGHT_SCRIPT}" >"${tmp_log}" 2>&1
rc=$?
set -e

[[ "${rc}" -ne 0 ]] || fail "preflight should fail deterministically when required env is missing"
assert_contains "${tmp_log}" 'Missing required environment variables:.*MANAGED_K8S_PROVIDER' \
  "preflight failure must mention MANAGED_K8S_PROVIDER"
assert_contains "${tmp_log}" 'Missing required environment variables:.*MANAGED_K8S_CONTEXT' \
  "preflight failure must mention MANAGED_K8S_CONTEXT"
pass "preflight fails deterministically with actionable missing-env guidance"

echo "[PASS] Managed-cloud bootstrap prerequisite validation passed"
