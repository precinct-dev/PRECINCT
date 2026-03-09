#!/usr/bin/env bash
# Validates biotech adaptation reference documentation + checklist artifact integrity.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

DOC_PATH="${POC_DIR}/docs/architecture/biotech-adaptation-reference-path.md"
ARTIFACT_PATH="${POC_DIR}/docs/architecture/artifacts/biotech-adaptation-reference-checklist.v1.json"

log_header "Validate Biotech Adaptation Reference"

if [ -f "${DOC_PATH}" ]; then
    log_pass "Reference document exists"
else
    log_fail "Reference document missing" "Expected ${DOC_PATH}"
fi

if [ -f "${ARTIFACT_PATH}" ]; then
    log_pass "Machine-readable checklist artifact exists"
else
    log_fail "Checklist artifact missing" "Expected ${ARTIFACT_PATH}"
fi

log_subheader "Path reference checks"
for path in \
    "docs/architecture/k8s-hardening-portability-matrix.md" \
    "docs/architecture/non-k8s-cloud-adaptation-guide.md" \
    "docs/architecture/compose-backport-decision-ledger.md" \
    "docs/architecture/artifacts/k8s-runtime-validation-report.v2.4.json" \
    "docs/architecture/artifacts/compose-backport-decision-ledger.v2.4.json" \
    "docs/compliance/immutable-audit-evidence-path.md"; do
    if [ -f "${POC_DIR}/${path}" ]; then
        log_pass "Referenced path exists: ${path}"
    else
        log_fail "Missing referenced path" "${path}"
    fi
done

if grep -qi "do not weaken controls" "${DOC_PATH}"; then
    log_pass "Do-not-weaken boundary guidance present"
else
    log_fail "Boundary guidance missing" "Expected 'do not weaken controls' language"
fi

log_subheader "Command example checks"
if make -C "${POC_DIR}" -n k8s-up >/dev/null; then
    log_pass "make -n k8s-up command example valid"
else
    log_fail "make -n k8s-up" "Command example failed"
fi

if make -C "${POC_DIR}" -n up >/dev/null; then
    log_pass "make -n up command example valid"
else
    log_fail "make -n up" "Command example failed"
fi

if bash "${POC_DIR}/tests/e2e/validate_setup_time.sh" k8s --dry-run >/dev/null; then
    log_pass "k8s setup-time dry-run command example valid"
else
    log_fail "k8s setup-time dry-run" "Command example failed"
fi

if bash "${POC_DIR}/tests/e2e/validate_setup_time.sh" compose --dry-run >/dev/null; then
    log_pass "compose setup-time dry-run command example valid"
else
    log_fail "compose setup-time dry-run" "Command example failed"
fi

if bash "${POC_DIR}/tests/validate_deployment_patterns.sh" >/dev/null; then
    log_pass "deployment patterns validation command example valid"
else
    log_fail "deployment patterns validation" "Command example failed"
fi

log_subheader "Checklist walkthrough validation"
if python3 - "${ARTIFACT_PATH}" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    doc = json.load(f)

assert doc["schema_version"] == "biotech.adaptation.reference.v1"
assert doc["k8s_first_baseline"]["required"] is True

positive = doc["walkthrough_examples"]["positive"]
negative = doc["walkthrough_examples"]["negative"]

assert positive["outcome"] == "accepted"
assert negative["outcome"] == "rejected"
assert len(negative.get("violated_invariants", [])) > 0

checklist = doc["non_k8s_adaptation_checklist"]
for key, value in checklist.items():
    assert value is True, f"{key} must be true"
PY
then
    log_pass "Positive/negative adaptation walkthrough artifact is consistent"
else
    log_fail "Checklist walkthrough validation" "Artifact content invalid"
fi

print_summary
