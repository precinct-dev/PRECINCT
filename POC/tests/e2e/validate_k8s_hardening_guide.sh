#!/usr/bin/env bash
# Validates Kubernetes-first hardening guide completeness and portability boundaries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GUIDE="${POC_ROOT}/docs/architecture/k8s-hardening-portability-matrix.md"
ARCH_DOC="${POC_ROOT}/docs/ARCHITECTURE.md"
DEPLOY_DOC="${POC_ROOT}/docs/deployment-guide.md"

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf "  PASS: %s\n" "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf "  FAIL: %s\n" "$1"
}

require_file() {
  local path="$1"
  if [ -f "${path}" ]; then
    pass "Found file: ${path}"
  else
    fail "Missing file: ${path}"
  fi
}

echo "validate_k8s_hardening_guide: start"

require_file "${GUIDE}"
require_file "${ARCH_DOC}"
require_file "${DEPLOY_DOC}"

if [ ! -f "${GUIDE}" ]; then
  echo "validate_k8s_hardening_guide: FAIL (guide missing)"
  exit 1
fi

if grep -q "| Control | Runtime Class |" "${GUIDE}"; then
  pass "Control matrix header exists"
else
  fail "Control matrix header missing"
fi

for klass in portable compose-limited k8s-native; do
  if grep -qi "|[[:space:]]*${klass}[[:space:]]*|" "${GUIDE}"; then
    pass "Runtime class present: ${klass}"
  else
    fail "Runtime class missing: ${klass}"
  fi
done

compose_rows="$(awk -F'|' 'tolower($0) ~ /\|[[:space:]]*compose-limited[[:space:]]*\|/ {print $0}' "${GUIDE}")"
if [ -n "${compose_rows}" ]; then
  pass "compose-limited rows detected"
else
  fail "No compose-limited rows found"
fi

if [ -n "${compose_rows}" ]; then
  while IFS= read -r row; do
    fallback="$(printf '%s\n' "${row}" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $5); print $5}')"
    control="$(printf '%s\n' "${row}" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2}')"
    if [ -z "${fallback}" ] || [ "${fallback}" = "N/A" ] || [ "${fallback}" = "-" ]; then
      fail "Compose fallback missing for control: ${control}"
    else
      pass "Compose fallback documented for control: ${control}"
    fi
  done <<< "${compose_rows}"
fi

if grep -q "architecture/k8s-hardening-portability-matrix.md" "${ARCH_DOC}"; then
  pass "ARCHITECTURE.md links hardening guide"
else
  fail "ARCHITECTURE.md missing hardening guide link"
fi

if grep -q "architecture/k8s-hardening-portability-matrix.md" "${DEPLOY_DOC}"; then
  pass "deployment-guide.md links hardening guide"
else
  fail "deployment-guide.md missing hardening guide link"
fi

if make -C "${POC_ROOT}" -n k8s-up >/dev/null 2>&1; then
  pass "make -n k8s-up validated"
else
  fail "make -n k8s-up failed"
fi

if make -C "${POC_ROOT}" -n up >/dev/null 2>&1; then
  pass "make -n up validated"
else
  fail "make -n up failed"
fi

if grep -q "## Verification Checklist" "${GUIDE}"; then
  pass "Verification checklist section exists"
else
  fail "Verification checklist section missing"
fi

if [ "${FAIL_COUNT}" -ne 0 ]; then
  echo "validate_k8s_hardening_guide: FAIL (${FAIL_COUNT} failed, ${PASS_COUNT} passed)"
  exit 1
fi

echo "validate_k8s_hardening_guide: PASS (${PASS_COUNT} checks)"
