#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

RUNBOOK_INCIDENT="${POC_DIR}/docs/operations/runbooks/openclaw-incident-triage-and-response.md"
RUNBOOK_ROLLBACK="${POC_DIR}/docs/operations/runbooks/openclaw-rollback-and-recovery.md"
OWNERSHIP_DOC="${POC_DIR}/docs/operations/openclaw-control-ownership-matrix.md"
DRILL_JSON="${POC_DIR}/docs/operations/artifacts/openclaw-operations-drill-latest.json"
DRILL_MD="${POC_DIR}/docs/operations/artifacts/openclaw-operations-drill-latest.md"

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
assert_file "${OWNERSHIP_DOC}"
assert_file "${DRILL_JSON}"
assert_file "${DRILL_MD}"

assert_contains "${RUNBOOK_INCIDENT}" '/tools/invoke' "incident runbook must include OpenClaw tool incident probe"
assert_contains "${RUNBOOK_INCIDENT}" 'go run ./cmd/openclaw-ws-smoke' "incident runbook must include live OpenClaw WS smoke probe"
assert_contains "${RUNBOOK_INCIDENT}" 'docker compose restart precinct-gateway' "incident runbook must include containment restart"
assert_contains "${RUNBOOK_INCIDENT}" "TestGatewayAuthz_OpenClawWSDenyMatrix_Integration" "incident runbook must include WS authz verification command"
assert_contains "${RUNBOOK_ROLLBACK}" 'make compose-production-intent-preflight' "rollback runbook must include compose preflight"
assert_contains "${RUNBOOK_ROLLBACK}" 'go run ./cmd/openclaw-ws-smoke' "rollback runbook must include live OpenClaw WS smoke probe"
assert_contains "${RUNBOOK_ROLLBACK}" 'kustomize build deploy/terraform/overlays/staging' "rollback runbook must include k8s rollback command"
assert_contains "${RUNBOOK_ROLLBACK}" 'make operations-readiness-validate' "rollback runbook must include readiness validation command"

for control in Authn Authz Policy Audit Egress Approvals; do
  assert_contains "${OWNERSHIP_DOC}" "${control}" "ownership matrix missing control row: ${control}"
done
assert_contains "${OWNERSHIP_DOC}" 'Primary Owner' "ownership matrix must include owner mapping"
assert_contains "${OWNERSHIP_DOC}" 'SLO / Escalation Target' "ownership matrix must include escalation target"

status="$(jq -r '.status // empty' "${DRILL_JSON}")"
[[ "${status}" == "pass" ]] || fail "openclaw operations drill status must be pass"

generated_date="$(jq -r '.generated_at // empty' "${DRILL_JSON}" | cut -d'T' -f1)"
today_utc="$(date -u +%Y-%m-%d)"
[[ "${generated_date}" == "${today_utc}" ]] || fail "openclaw operations drill is stale: expected ${today_utc}, got ${generated_date}"

jq -e '.steps[] | select(.name=="incident_trigger_deny" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "incident_trigger_deny step missing or not pass"
jq -e '.steps[] | select(.name=="ws_probe_pre_restart" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "ws_probe_pre_restart step missing or not pass"
jq -e '.steps[] | select(.name=="containment_restart" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "containment_restart step missing or not pass"
jq -e '.steps[] | select(.name=="rollback_preflight" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "rollback_preflight step missing or not pass"
jq -e '.steps[] | select(.name=="post_recovery_deny_check" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "post_recovery_deny_check step missing or not pass"
jq -e '.steps[] | select(.name=="ws_probe_post_restart" and .status=="pass")' "${DRILL_JSON}" >/dev/null \
  || fail "ws_probe_post_restart step missing or not pass"

while IFS= read -r rel_path; do
  [[ -z "${rel_path}" ]] && continue
  abs_path="${POC_DIR}/${rel_path}"
  [[ -e "${abs_path}" ]] || fail "drill artifact path does not exist: ${rel_path}"
done < <(jq -r '.artifacts[]' "${DRILL_JSON}")

echo "[PASS] OpenClaw operations runbook pack validation passed"
