#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

CONTRACT_DOC="${POC_DIR}/docs/security/compose-signature-prerequisite-contract.md"
RUNBOOK_DOC="${POC_DIR}/docs/operations/runbooks/compose-signature-credential-injection.md"
PREFLIGHT_SCRIPT="${POC_DIR}/scripts/compose-production-intent-preflight.sh"

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

require_cmd rg

[[ -f "${CONTRACT_DOC}" ]] || fail "missing signature prerequisite contract doc: ${CONTRACT_DOC}"
[[ -f "${RUNBOOK_DOC}" ]] || fail "missing credential injection runbook: ${RUNBOOK_DOC}"
[[ -f "${PREFLIGHT_SCRIPT}" ]] || fail "missing compose preflight script: ${PREFLIGHT_SCRIPT}"
pass "signature prerequisite docs and preflight script exist"

assert_contains "${CONTRACT_DOC}" 'COMPOSE_PROD_REGISTRY_USERNAME' \
  "contract must mention COMPOSE_PROD_REGISTRY_USERNAME"
assert_contains "${CONTRACT_DOC}" 'COMPOSE_PROD_REGISTRY_TOKEN' \
  "contract must mention COMPOSE_PROD_REGISTRY_TOKEN"
assert_contains "${CONTRACT_DOC}" 'No silent skip path|No silent skip' \
  "contract must state fail-closed/no-silent-skip behavior"
assert_contains "${RUNBOOK_DOC}" 'Never commit' \
  "runbook must include no-committed-secrets rule"
assert_contains "${RUNBOOK_DOC}" 'unset COMPOSE_PROD_REGISTRY_TOKEN' \
  "runbook must include credential cleanup step"
pass "contract and runbook include required guidance"

tmp_log="$(mktemp)"
set +e
COMPOSE_PROD_VERIFY_SIGNATURE=1 \
COMPOSE_PROD_REGISTRY_USERNAME= \
COMPOSE_PROD_REGISTRY_TOKEN= \
bash "${PREFLIGHT_SCRIPT}" >"${tmp_log}" 2>&1
rc=$?
set -e

[[ "${rc}" -ne 0 ]] || fail "live signature mode should fail when registry credential inputs are missing"
assert_contains "${tmp_log}" 'Missing required environment variables for live signature mode:.*COMPOSE_PROD_REGISTRY_USERNAME' \
  "preflight fail output must mention COMPOSE_PROD_REGISTRY_USERNAME"
assert_contains "${tmp_log}" 'Missing required environment variables for live signature mode:.*COMPOSE_PROD_REGISTRY_TOKEN' \
  "preflight fail output must mention COMPOSE_PROD_REGISTRY_TOKEN"
pass "live signature mode missing-credential failure is deterministic and actionable"

echo "[PASS] Compose signature prerequisite validation passed"
