#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

MITRE_JSON="${POC_DIR}/docs/security/artifacts/mitre-atlas-signal-mapping.v1.json"
OWASP_JSON="${POC_DIR}/docs/security/artifacts/owasp-agentic-top10-signal-mapping.v1.json"
MAPPING_DOC="${POC_DIR}/docs/security/framework-taxonomy-signal-mappings.md"

required_signal_keys=(
  "availability.rate_limited"
  "content.blocked"
  "data.pii_detected"
  "policy.authorization_denied"
  "policy.step_up_blocked"
  "prompt.injection_blocked"
  "prompt.injection_detected"
  "prompt.jailbreak_detected"
  "tool.hash_unverified"
)

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

require_cmd jq
require_cmd rg

[[ -f "${MITRE_JSON}" ]] || fail "missing MITRE mapping artifact: ${MITRE_JSON}"
[[ -f "${OWASP_JSON}" ]] || fail "missing OWASP mapping artifact: ${OWASP_JSON}"
[[ -f "${MAPPING_DOC}" ]] || fail "missing taxonomy mapping doc: ${MAPPING_DOC}"
pass "mapping docs and artifacts exist"

jq -e '.schema_version == "framework_signal_mapping.mitre_atlas.v1"' "${MITRE_JSON}" >/dev/null \
  || fail "unexpected MITRE mapping schema version"
jq -e '.schema_version == "framework_signal_mapping.owasp_agentic_top10.v1"' "${OWASP_JSON}" >/dev/null \
  || fail "unexpected OWASP mapping schema version"
pass "mapping schemas are valid"

for key in "${required_signal_keys[@]}"; do
  jq -e --arg key "${key}" '.mappings[$key] and (.mappings[$key] | length > 0)' "${MITRE_JSON}" >/dev/null \
    || fail "missing MITRE mapping for signal key: ${key}"
  jq -e --arg key "${key}" '.mappings[$key] and (.mappings[$key] | length > 0)' "${OWASP_JSON}" >/dev/null \
    || fail "missing OWASP mapping for signal key: ${key}"
done
pass "required signal key coverage is complete for MITRE and OWASP catalogs"

if jq -e '.mappings | to_entries[] | .value[] | test("^AML\\.T[0-9]{4}$") | not' "${MITRE_JSON}" >/dev/null; then
  fail "found MITRE mapping identifier with unexpected format"
fi
if jq -e '.mappings | to_entries[] | .value[] | test("^ASI[0-9]{2}$") | not' "${OWASP_JSON}" >/dev/null; then
  fail "found OWASP mapping identifier with unexpected format"
fi
pass "identifier formats are valid (MITRE AML.Txxxx, OWASP ASIxx)"

for key in "${required_signal_keys[@]}"; do
  rg -n -F "${key}" "${MAPPING_DOC}" >/dev/null 2>&1 || fail "mapping doc missing signal key row: ${key}"
done
pass "mapping matrix doc includes all required signal keys"

echo "[PASS] Framework taxonomy mapping validation passed"
