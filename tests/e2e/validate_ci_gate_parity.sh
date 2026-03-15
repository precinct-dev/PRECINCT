#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
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

assert_not_contains() {
  local pattern="$1"
  local message="$2"
  if rg -n --pcre2 "${pattern}" "${WORKFLOW_PATH}" >/dev/null 2>&1; then
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

# Trigger policy: manual only (no automatic CI spend)
assert_multiline '^on:\n  workflow_dispatch:' "workflow must be manual-only (workflow_dispatch)"
assert_not_contains '^  push:' "push trigger must not be declared"
assert_not_contains '^  pull_request:' "pull_request trigger must not be declared"
assert_not_contains '^  schedule:' "schedule trigger must not be declared"

# Manual readiness gate coverage
assert_contains 'make strict-runtime-validate' "readiness-gates must execute strict runtime validation"
assert_contains 'make production-readiness-validate' "readiness-gates must execute production readiness validation"
assert_contains 'name:\s+readiness-gates' "readiness artifact upload must be present"

# Manual demo parity coverage
assert_contains 'make phoenix-up' "demo-compose-gate must bring up phoenix stack"
assert_contains 'make demo-compose' "demo-compose-gate must execute demo-compose"
assert_contains 'name:\s+demo-compose-gate' "demo-compose artifact upload must be present"

# Manual K8s policy gate
assert_contains 'make k8s-validate' "k8s policy gate must run k8s-validate"

# Build path still wired behind readiness/demo gates when manually invoked
assert_contains 'needs:\s+\[lint, test, opa-test, readiness-gates, demo-compose-gate\]' \
  "build-and-push must depend on readiness and demo parity gates"

echo "[PASS] CI gate parity validation passed"
