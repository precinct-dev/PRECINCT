#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEFAULT_PACK_JSON="${ROOT_DIR}/packs/openclaw/pack.v1.json"
PACK_JSON="${1:-${DEFAULT_PACK_JSON}}"
ARCH_DOC="${ROOT_DIR}/docs/architecture/app-integration-pack-model.md"
SDK_DOC="${ROOT_DIR}/docs/sdk/app-pack-authoring-guide.md"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

[[ -f "${ARCH_DOC}" ]] || fail "missing architecture doc: ${ARCH_DOC}"
[[ -f "${SDK_DOC}" ]] || fail "missing sdk authoring doc: ${SDK_DOC}"
[[ -f "${PACK_JSON}" ]] || fail "missing OpenClaw pack manifest: ${PACK_JSON}"

jq empty "${PACK_JSON}" >/dev/null 2>&1 || fail "pack manifest is not valid JSON"
pass "pack manifest parses as valid JSON"

schema="$(jq -r '.schema_version // ""' "${PACK_JSON}")"
[[ "${schema}" == "app.integration.pack.v1" ]] || fail "unexpected schema_version: ${schema}"
pass "schema version is app.integration.pack.v1"

pack_id="$(jq -r '.pack_id // ""' "${PACK_JSON}")"
[[ -n "${pack_id}" ]] || fail "pack_id must be set"
pass "pack_id present"

upstream_repo="$(jq -r '.upstream.repo // ""' "${PACK_JSON}")"
upstream_commit="$(jq -r '.upstream.commit // ""' "${PACK_JSON}")"
[[ -n "${upstream_repo}" ]] || fail "upstream.repo must be set"
[[ -n "${upstream_commit}" ]] || fail "upstream.commit must be set"
pass "upstream baseline metadata present"

no_upstream_mod="$(jq -r '.security_expectations.no_upstream_source_modification // false' "${PACK_JSON}")"
no_model_bypass="$(jq -r '.security_expectations.no_direct_model_bypass // false' "${PACK_JSON}")"
no_tool_bypass="$(jq -r '.security_expectations.no_direct_tool_bypass // false' "${PACK_JSON}")"
[[ "${no_upstream_mod}" == "true" ]] || fail "no_upstream_source_modification must be true"
[[ "${no_model_bypass}" == "true" ]] || fail "no_direct_model_bypass must be true"
[[ "${no_tool_bypass}" == "true" ]] || fail "no_direct_tool_bypass must be true"
pass "core security expectations preserved"

required_controls_count="$(jq -r '.security_expectations.required_controls | length' "${PACK_JSON}")"
[[ "${required_controls_count}" -ge 4 ]] || fail "required_controls must include at least 4 controls"
pass "required controls list present"

adapter_model_provider="$(jq -r '.adapter_contract.model_routing.default_provider // ""' "${PACK_JSON}")"
adapter_models_count="$(jq -r '.adapter_contract.model_routing.allowed_models | length' "${PACK_JSON}")"
adapter_tools_count="$(jq -r '.adapter_contract.tool_registration.required_tools | length' "${PACK_JSON}")"
adapter_hash_verification="$(jq -r '.adapter_contract.tool_registration.hash_verification // ""' "${PACK_JSON}")"
adapter_timeout_non_strict="$(jq -r '.adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_non_strict // ""' "${PACK_JSON}")"
adapter_timeout_strict="$(jq -r '.adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_strict // ""' "${PACK_JSON}")"
compose_hint_present="$(jq -r '.adapter_contract.runtime_profile_hints.compose.strict_deepscan' "${PACK_JSON}")"
k8s_hint_present="$(jq -r '.adapter_contract.runtime_profile_hints.k8s.strict_deepscan' "${PACK_JSON}")"

[[ -n "${adapter_model_provider}" ]] || fail "adapter_contract.model_routing.default_provider must be set"
[[ "${adapter_models_count}" -ge 1 ]] || fail "adapter_contract.model_routing.allowed_models must include at least one model"
[[ "${adapter_tools_count}" -ge 1 ]] || fail "adapter_contract.tool_registration.required_tools must include at least one tool"
[[ "${adapter_hash_verification}" == "required" ]] || fail "adapter_contract.tool_registration.hash_verification must be 'required'"
[[ "${adapter_timeout_non_strict}" == "accept_case26_gateway_timeout_variance" ]] || fail "adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_non_strict must be set"
[[ "${adapter_timeout_strict}" == "fail_closed" ]] || fail "adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_strict must be 'fail_closed'"
[[ "${compose_hint_present}" == "true" ]] || fail "adapter_contract.runtime_profile_hints.compose.strict_deepscan must be true"
[[ "${k8s_hint_present}" == "false" ]] || fail "adapter_contract.runtime_profile_hints.k8s.strict_deepscan must be false"
pass "adapter contract sections present (model routing, tool registration, guardrails, runtime profile hints)"

compose_cmd_count="$(jq -r '.runtime_validation.compose | length' "${PACK_JSON}")"
k8s_cmd_count="$(jq -r '.runtime_validation.k8s | length' "${PACK_JSON}")"
[[ "${compose_cmd_count}" -ge 1 ]] || fail "runtime_validation.compose must include commands"
[[ "${k8s_cmd_count}" -ge 1 ]] || fail "runtime_validation.k8s must include commands"
pass "runtime validation commands declared for compose and k8s"

grep -Eiq "core \(must stay agnostic\)" "${ARCH_DOC}" || fail "architecture doc missing core agnostic section"
grep -Eiq "app integration pack" "${ARCH_DOC}" || fail "architecture doc missing app pack section"
grep -Eiq "sdk adaptation layer" "${ARCH_DOC}" || fail "architecture doc missing sdk adaptation section"
pass "architecture doc includes core/sdk/pack boundaries"

grep -Eiq "authoring steps" "${SDK_DOC}" || fail "sdk authoring guide missing authoring steps"
grep -Eiq "anti-patterns" "${SDK_DOC}" || fail "sdk authoring guide missing anti-patterns"
grep -Eiq "generic migration recipe" "${SDK_DOC}" || fail "sdk authoring guide missing generic migration recipe"
pass "sdk authoring guide includes required sections"

echo "[PASS] App integration pack model validation passed"
