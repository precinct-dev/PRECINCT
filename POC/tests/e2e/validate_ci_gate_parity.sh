#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORKFLOW_PATH="${REPO_ROOT}/.github/workflows/ci.yaml"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

assert_contains() {
  local pattern="$1"
  local message="$2"
  if ! rg -n --pcre2 "${pattern}" "${WORKFLOW_PATH}" >/dev/null 2>&1; then
    fail "${message}"
  fi
}

assert_multiline() {
  local pattern="$1"
  local message="$2"
  if ! rg -n -U --pcre2 "${pattern}" "${WORKFLOW_PATH}" >/dev/null 2>&1; then
    fail "${message}"
  fi
}

[ -f "${WORKFLOW_PATH}" ] || fail "workflow not found: ${WORKFLOW_PATH}"

echo "[INFO] Validating CI parity workflow policy at ${WORKFLOW_PATH}"

# Trigger/policy coverage
assert_contains '^  schedule:' "schedule trigger must be declared"
assert_contains 'cron:\s*"0 9 \* \* \*"' "expected daily schedule trigger missing"

# PR-required readiness gate
assert_multiline 'readiness-gates:\n(?:.*\n)*?\s+if:\s+github\.event_name != '\''schedule'\''' \
  "readiness-gates job must be non-scheduled (PR/push/manual)"
assert_contains 'make strict-runtime-validate' "readiness-gates must execute strict runtime validation"
assert_contains 'make production-readiness-validate' "readiness-gates must execute production readiness validation"
assert_contains 'name:\s+readiness-gates' "readiness artifact upload must be present"

# PR-required demo parity gate
assert_multiline 'demo-compose-gate:\n(?:.*\n)*?\s+if:\s+github\.event_name != '\''schedule'\''' \
  "demo-compose-gate job must be non-scheduled (PR/push/manual)"
assert_contains 'make phoenix-up' "demo-compose-gate must bring up phoenix stack"
assert_contains 'make demo-compose' "demo-compose-gate must execute demo-compose"
assert_contains 'name:\s+demo-compose-gate' "demo-compose artifact upload must be present"

# Scheduled/manual K8s policy gate
assert_multiline 'k8s-validation-policy-gate:\n(?:.*\n)*?\s+if:\s+github\.event_name == '\''schedule'\'' \|\| github\.event_name == '\''workflow_dispatch'\''' \
  "k8s validation policy gate must be schedule/manual only"
assert_contains 'make k8s-validate' "k8s policy gate must run k8s-validate"

# Build must be blocked on required PR gates
assert_contains 'needs:\s+\[lint, test, opa-test, readiness-gates, demo-compose-gate\]' \
  "build-and-push must depend on readiness and demo parity gates"

echo "[PASS] CI gate parity validation passed"
