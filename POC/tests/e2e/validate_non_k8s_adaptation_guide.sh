#!/usr/bin/env bash
# Validates non-K8s adaptation guide coverage and runs sample checklist commands.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GUIDE="${POC_ROOT}/docs/architecture/non-k8s-cloud-adaptation-guide.md"
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

require_contains() {
  local pattern="$1"
  local label="$2"
  if grep -q "${pattern}" "${GUIDE}"; then
    pass "${label}"
  else
    fail "${label}"
  fi
}

echo "validate_non_k8s_adaptation_guide: start"

if [ -f "${GUIDE}" ]; then
  pass "Guide file exists"
else
  fail "Guide file missing"
  echo "validate_non_k8s_adaptation_guide: FAIL (guide missing)"
  exit 1
fi

require_contains "## Runtime-Agnostic Core Invariant Mapping" "Invariant mapping section exists"
require_contains "## Missing Kubernetes Primitive Compensating Controls" "Compensating controls section exists"
require_contains "## Verification Checklist (Operator Sign-Off)" "Verification checklist section exists"
require_contains "## Anti-Patterns (Do Not Do This)" "Anti-pattern warning section exists"
require_contains "## Adaptation Scenario Walkthrough" "Adaptation walkthrough section exists"
require_contains "do not weaken invariants" "Explicit do-not-weaken warning exists"
require_contains "Positive Path (Accepted)" "Positive walkthrough exists"
require_contains "Negative Path (Rejected)" "Negative walkthrough exists"

for inv in INV-01 INV-02 INV-03 INV-04 INV-05 INV-06 INV-07 INV-08 INV-09 INV-10 INV-11 INV-12; do
  if grep -q "${inv}" "${GUIDE}"; then
    pass "Invariant listed: ${inv}"
  else
    fail "Invariant missing: ${inv}"
  fi
done

for primitive in "NetworkPolicy" "Pod Security Admission" "Admission webhooks" "IRSA workload IAM federation" "k8s_psat node attestation" "Encrypted PVC defaults"; do
  if grep -q "${primitive}" "${GUIDE}"; then
    pass "Compensating control mapped: ${primitive}"
  else
    fail "Compensating control missing: ${primitive}"
  fi
done

if [ -f "${DEPLOY_DOC}" ] && grep -q "non-k8s-cloud-adaptation-guide.md" "${DEPLOY_DOC}"; then
  pass "deployment-guide.md links adaptation guide"
else
  fail "deployment-guide.md missing adaptation guide link"
fi

if make -C "${POC_ROOT}" -n up >/dev/null 2>&1; then
  pass "Checklist sample command pass: make -n up"
else
  fail "Checklist sample command fail: make -n up"
fi

if make -C "${POC_ROOT}" k8s-validate >/dev/null 2>&1; then
  pass "Checklist sample command pass: make k8s-validate"
else
  fail "Checklist sample command fail: make k8s-validate"
fi

if bash "${POC_ROOT}/tests/e2e/validate_k8s_hardening_guide.sh" >/dev/null 2>&1; then
  pass "Checklist sample command pass: validate_k8s_hardening_guide.sh"
else
  fail "Checklist sample command fail: validate_k8s_hardening_guide.sh"
fi

if bash "${POC_ROOT}/tests/e2e/validate_setup_time.sh" compose --dry-run >/dev/null 2>&1; then
  pass "Checklist sample command pass: validate_setup_time compose --dry-run"
else
  fail "Checklist sample command fail: validate_setup_time compose --dry-run"
fi

if bash "${POC_ROOT}/tests/validate_deployment_patterns.sh" >/dev/null 2>&1; then
  pass "Checklist sample command pass: validate_deployment_patterns.sh"
else
  fail "Checklist sample command fail: validate_deployment_patterns.sh"
fi

if [ "${FAIL_COUNT}" -ne 0 ]; then
  echo "validate_non_k8s_adaptation_guide: FAIL (${FAIL_COUNT} failed, ${PASS_COUNT} passed)"
  exit 1
fi

echo "validate_non_k8s_adaptation_guide: PASS (${PASS_COUNT} checks)"
