#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

RUNBOOK_INCIDENT="${POC_DIR}/docs/operations/runbooks/incident-triage-and-response.md"
RUNBOOK_ROLLBACK="${POC_DIR}/docs/operations/runbooks/rollback-runbook.md"
RUNBOOK_SECURITY="${POC_DIR}/docs/operations/runbooks/security-event-response.md"
SLO_DOC="${POC_DIR}/docs/operations/slo-sli-ownership.md"
DRILL_JSON="${POC_DIR}/docs/operations/artifacts/backup-restore-drill-latest.json"
DRILL_MD="${POC_DIR}/docs/operations/artifacts/backup-restore-drill-latest.md"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

assert_file() {
  local file="$1"
  [[ -f "${file}" ]] || fail "missing required file: ${file}"
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local message="$3"
  rg -n --pcre2 "${pattern}" "${file}" >/dev/null 2>&1 || fail "${message}"
}

require_cmd jq
require_cmd rg

assert_file "${RUNBOOK_INCIDENT}"
assert_file "${RUNBOOK_ROLLBACK}"
assert_file "${RUNBOOK_SECURITY}"
assert_file "${SLO_DOC}"
assert_file "${DRILL_JSON}"
assert_file "${DRILL_MD}"

assert_contains "${RUNBOOK_INCIDENT}" 'make up' "incident runbook must reference compose bring-up path"
assert_contains "${RUNBOOK_INCIDENT}" 'docker compose logs' "incident runbook must include log capture commands"
assert_contains "${RUNBOOK_ROLLBACK}" 'make compose-production-intent-preflight' "rollback runbook must include production-intent preflight"
assert_contains "${RUNBOOK_ROLLBACK}" 'kustomize build deploy/terraform/overlays/staging' "rollback runbook must include k8s rollback path"
assert_contains "${RUNBOOK_SECURITY}" 'make promotion-identity-validate' "security runbook must include promotion identity verification"
assert_contains "${RUNBOOK_SECURITY}" 'make compose-production-intent-validate' "security runbook must include compose production-intent gate"
assert_contains "${SLO_DOC}" 'Primary Owner' "SLO/SLI doc must include ownership mapping"
assert_contains "${SLO_DOC}" 'Escalation SLA' "SLO/SLI doc must include escalation targets"

status="$(jq -r '.status // empty' "${DRILL_JSON}")"
[[ "${status}" == "pass" ]] || fail "backup/restore drill status must be pass"

generated_date="$(jq -r '.generated_at // empty' "${DRILL_JSON}" | cut -d'T' -f1)"
[[ -n "${generated_date}" ]] || fail "backup/restore drill must include generated_at"

jq -e '.steps[] | select(.name=="keydb_backup_restore" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "keydb backup/restore step missing or not pass"
jq -e '.steps[] | select(.name=="spike_nexus_backup_restore" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "spike backup/restore step missing or not pass"
jq -e '.steps[] | select(.name=="audit_log_backup_restore" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "audit backup/restore step missing or not pass"
jq -e '.runtime_artifacts_tracked == false' "${DRILL_JSON}" >/dev/null \
  || fail "backup/restore drill must mark runtime artifacts as untracked workspace outputs"
jq -e '.runtime_artifacts | length >= 3' "${DRILL_JSON}" >/dev/null \
  || fail "backup/restore drill must describe runtime backup outputs"

while IFS= read -r rel_path; do
  [[ -z "${rel_path}" ]] && continue
  abs_path="${POC_DIR}/${rel_path}"
  [[ -e "${abs_path}" ]] || fail "drill artifact path does not exist: ${rel_path}"
done < <(jq -r '.artifacts[]' "${DRILL_JSON}")

echo "[PASS] Operational readiness pack validation passed"
