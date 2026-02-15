#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
STRICT_COMPOSE_FILE="${ROOT_DIR}/docker-compose.strict.yml"
PROD_COMPOSE_FILE="${ROOT_DIR}/docker-compose.prod-intent.yml"
POLICY_FILE="${COMPOSE_PROD_POLICY_FILE:-${ROOT_DIR}/config/compose-production-intent-policy.json}"
ENV_FILE="${COMPOSE_PROD_ENV_FILE:-${ROOT_DIR}/config/compose-production-intent.env}"
VERIFY_SIGNATURES="${COMPOSE_PROD_VERIFY_SIGNATURE:-0}"

# Strict profile compose config resolution requires these env vars.
export STRICT_UPSTREAM_URL="${STRICT_UPSTREAM_URL:-https://strict-upstream.example.com/mcp}"
export APPROVAL_SIGNING_KEY="${APPROVAL_SIGNING_KEY:-compose-production-intent-approval-key-material-32chars}"
export UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="${UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS:-spiffe://poc.local/ns/tools/sa/mcp-tool}"
export KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="${KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS:-spiffe://poc.local/ns/data/sa/keydb}"

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

require_cmd docker
require_cmd jq

[[ -f "${BASE_COMPOSE_FILE}" ]] || fail "missing compose file: ${BASE_COMPOSE_FILE}"
[[ -f "${STRICT_COMPOSE_FILE}" ]] || fail "missing compose file: ${STRICT_COMPOSE_FILE}"
[[ -f "${PROD_COMPOSE_FILE}" ]] || fail "missing compose file: ${PROD_COMPOSE_FILE}"
[[ -f "${POLICY_FILE}" ]] || fail "missing policy file: ${POLICY_FILE}"
[[ -f "${ENV_FILE}" ]] || fail "missing env lock file: ${ENV_FILE}"

schema_version="$(jq -r '.schema_version // empty' "${POLICY_FILE}")"
[[ "${schema_version}" == "compose_production_intent_supply_chain_policy.v1" ]] \
  || fail "unexpected policy schema version: ${schema_version}"

registry_prefix="$(jq -r '.artifact_source.registry // empty' "${POLICY_FILE}")"
repository_prefix="$(jq -r '.artifact_source.repository // empty' "${POLICY_FILE}")"
[[ -n "${registry_prefix}" ]] || fail "policy missing artifact_source.registry"
[[ -n "${repository_prefix}" ]] || fail "policy missing artifact_source.repository"
required_image_prefix="${registry_prefix}/${repository_prefix}/"

# Load env lock into shell environment to resolve expected image refs.
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

compose_cfg_json="$(docker compose \
  --profile strict \
  --env-file "${ENV_FILE}" \
  -f "${BASE_COMPOSE_FILE}" \
  -f "${STRICT_COMPOSE_FILE}" \
  -f "${PROD_COMPOSE_FILE}" \
  config --format json)"

services_count="$(jq '.required_services | length' "${POLICY_FILE}")"
[[ "${services_count}" -gt 0 ]] || fail "policy required_services must not be empty"

while IFS=$'\t' read -r service_name env_var cert_regex cert_issuer; do
  [[ -n "${service_name}" ]] || continue
  [[ -n "${env_var}" ]] || fail "service ${service_name} missing image_env in policy"
  [[ -n "${cert_regex}" ]] || fail "service ${service_name} missing cosign certificate_identity_regex"
  [[ -n "${cert_issuer}" ]] || fail "service ${service_name} missing cosign certificate_oidc_issuer"

  service_present="$(echo "${compose_cfg_json}" | jq -r --arg svc "${service_name}" \
    'if .services[$svc] then "1" else "0" end')"
  [[ "${service_present}" == "1" ]] || fail "service ${service_name} missing from production-intent compose config"

  pull_policy="$(echo "${compose_cfg_json}" | jq -r --arg svc "${service_name}" \
    '.services[$svc].pull_policy // empty')"
  [[ "${pull_policy}" == "always" ]] || fail "service ${service_name} must set pull_policy=always for production-intent path"

  image_ref="$(echo "${compose_cfg_json}" | jq -r --arg svc "${service_name}" \
    '.services[$svc].image // empty')"
  [[ -n "${image_ref}" ]] || fail "service ${service_name} missing image reference in production-intent compose config"
  [[ "${image_ref}" =~ @sha256:[a-f0-9]{64}$ ]] || fail "service ${service_name} image is not digest pinned: ${image_ref}"
  [[ "${image_ref}" == "${required_image_prefix}"* ]] || fail "service ${service_name} image not from allowed prefix ${required_image_prefix}: ${image_ref}"

  expected_ref="${!env_var:-}"
  [[ -n "${expected_ref}" ]] || fail "env var ${env_var} is not set from ${ENV_FILE}"
  [[ "${expected_ref}" == "${image_ref}" ]] \
    || fail "service ${service_name} image does not match ${env_var}: expected ${expected_ref}, got ${image_ref}"

  if [[ "${VERIFY_SIGNATURES}" == "1" ]]; then
    require_cmd cosign
    cosign verify \
      --certificate-identity-regexp="${cert_regex}" \
      --certificate-oidc-issuer="${cert_issuer}" \
      "${image_ref}" >/dev/null
  fi

  pass "${service_name} production-intent image + provenance policy wiring validated"
done < <(jq -r '
  .required_services
  | to_entries[]
  | [
      .key,
      (.value.image_env // ""),
      (.value.cosign.certificate_identity_regex // ""),
      (.value.cosign.certificate_oidc_issuer // "")
    ]
  | @tsv
' "${POLICY_FILE}")

if [[ "${VERIFY_SIGNATURES}" == "1" ]]; then
  pass "cosign signature verification completed for all production-intent services"
else
  echo "[INFO] Signature verification skipped (set COMPOSE_PROD_VERIFY_SIGNATURE=1 to enforce live cosign checks)."
fi

pass "Compose production-intent supply-chain preflight passed"
