#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAYBOOK_DOC="${ROOT_DIR}/docs/sdk/no-upstream-mod-integration-playbook.md"
ARCH_DOC="${ROOT_DIR}/docs/architecture/app-integration-pack-model.md"
SDK_DOC="${ROOT_DIR}/docs/sdk/app-pack-authoring-guide.md"
DEPLOY_DOC="${ROOT_DIR}/docs/deployment-guide.md"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  if ! grep -Eiq "${pattern}" "${file}"; then
    fail "${message}"
  fi
}

[[ -f "${PLAYBOOK_DOC}" ]] || fail "missing playbook doc: ${PLAYBOOK_DOC}"
[[ -f "${ARCH_DOC}" ]] || fail "missing architecture doc: ${ARCH_DOC}"
[[ -f "${SDK_DOC}" ]] || fail "missing sdk doc: ${SDK_DOC}"
[[ -f "${DEPLOY_DOC}" ]] || fail "missing deployment doc: ${DEPLOY_DOC}"
pass "required documents exist"

assert_contains "${PLAYBOOK_DOC}" "^## Zero-Upstream-Modification Model" \
  "playbook missing Zero-Upstream-Modification Model section"
assert_contains "${PLAYBOOK_DOC}" "^## Boundary Invariants" \
  "playbook missing Boundary Invariants section"
assert_contains "${PLAYBOOK_DOC}" "^## Tradeoff Matrix" \
  "playbook missing Tradeoff Matrix section"
assert_contains "${PLAYBOOK_DOC}" "^## Greenfield Build Path" \
  "playbook missing Greenfield Build Path section"
assert_contains "${PLAYBOOK_DOC}" "^### Compose Validation Gates" \
  "playbook missing Compose Validation Gates section"
assert_contains "${PLAYBOOK_DOC}" "^### Kubernetes Validation Gates" \
  "playbook missing Kubernetes Validation Gates section"
pass "playbook includes required sections"

assert_contains "${PLAYBOOK_DOC}" "pack-only" \
  "playbook must include pack-only strategy tradeoff"
assert_contains "${PLAYBOOK_DOC}" "sdk-only" \
  "playbook must include sdk-only strategy tradeoff"
assert_contains "${PLAYBOOK_DOC}" "hybrid pack\\+sdk" \
  "playbook must include hybrid pack+sdk strategy tradeoff"
assert_contains "${PLAYBOOK_DOC}" "No app-specific route logic in core middleware" \
  "playbook must include no app-specific core logic invariant"
pass "tradeoff matrix and invariants are explicit"

assert_contains "${PLAYBOOK_DOC}" "bash tests/e2e/validate_app_integration_pack_model.sh" \
  "playbook must include pack model validator command"
assert_contains "${PLAYBOOK_DOC}" "bash tests/e2e/validate_gateway_bypass_case26.sh" \
  "playbook must include gateway bypass validator command"
assert_contains "${PLAYBOOK_DOC}" "make demo-compose" \
  "playbook must include compose validation command"
assert_contains "${PLAYBOOK_DOC}" "make demo-k8s" \
  "playbook must include k8s validation command"
pass "compose and k8s validation gates are documented"

assert_contains "${ARCH_DOC}" "docs/sdk/no-upstream-mod-integration-playbook.md" \
  "architecture doc must link to no-upstream-mod playbook"
assert_contains "${SDK_DOC}" "docs/sdk/no-upstream-mod-integration-playbook.md" \
  "sdk doc must link to no-upstream-mod playbook"
assert_contains "${DEPLOY_DOC}" "No-Upstream-Modification Integration Playbook" \
  "deployment guide must reference no-upstream-mod integration playbook"
pass "cross-document links to playbook are present"

echo "[PASS] App integration strategy docs validation passed"
