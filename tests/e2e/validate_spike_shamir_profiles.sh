#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
POC_DIR="${ROOT_DIR}"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"
DC="docker compose -f ${COMPOSE_FILE}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

csv_count() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    echo 0
    return
  fi
  printf '%s\n' "${value}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' '
}

compose_env_value() {
  local cfg_json="$1"
  local service="$2"
  local key="$3"
  jq -r --arg svc "${service}" --arg key "${key}" '.services[$svc].environment[$key] // empty' "${cfg_json}"
}

render_doc() {
  local kind="$1"
  local name="$2"
  local file="$3"
  awk -v kind="${kind}" -v name="${name}" '
    BEGIN { RS="---" }
    $0 ~ ("kind:[[:space:]]*" kind "([[:space:]]|$)") && $0 ~ ("name:[[:space:]]*" name "([[:space:]]|$)") {
      print
      exit
    }
  ' "${file}"
}

doc_key_value() {
  local doc="$1"
  local key="$2"
  printf '%s\n' "${doc}" | awk -v key="${key}" '
    $0 ~ ("^[[:space:]]*" key ":[[:space:]]*") {
      value=$0
      sub("^[[:space:]]*" key ":[[:space:]]*", "", value)
      gsub(/["'\''[:space:]]/, "", value)
      print value
      exit
    }
  '
}

job_env_value() {
  local file="$1"
  local key="$2"
  awk -v key="${key}" '
    $1 == "-" && $2 == "name:" && $3 == key {
      want=1
      next
    }
    want && $1 == "value:" {
      value=$2
      gsub(/["'\'']/,"", value)
      print value
      exit
    }
  ' "${file}"
}

assert_demo_profile() {
  local label="$1"
  local threshold="$2"
  local shares="$3"
  local peers="$4"
  local peer_count
  peer_count="$(csv_count "${peers}")"

  [[ "${threshold}" == "1" ]] || fail "${label}: threshold must stay 1 for demo/dev bootstrap (got ${threshold})"
  [[ "${shares}" == "1" ]] || fail "${label}: shares must stay 1 for demo/dev bootstrap (got ${shares})"
  [[ "${peer_count}" == "1" ]] || fail "${label}: keeper peer list must stay single-node for demo/dev bootstrap (got ${peer_count})"
}

assert_release_profile() {
  local label="$1"
  local threshold="$2"
  local shares="$3"
  local peers="$4"
  local peer_count
  peer_count="$(csv_count "${peers}")"

  [[ "${threshold}" =~ ^[0-9]+$ ]] || fail "${label}: threshold is not numeric (${threshold})"
  [[ "${shares}" =~ ^[0-9]+$ ]] || fail "${label}: shares is not numeric (${shares})"
  (( threshold >= 2 )) || fail "${label}: threshold must be >= 2 (got ${threshold})"
  (( shares >= 3 )) || fail "${label}: shares must be >= 3 (got ${shares})"
  (( shares >= threshold )) || fail "${label}: shares must be >= threshold (got ${threshold}-of-${shares})"
  (( peer_count >= shares )) || fail "${label}: keeper peer list must provide at least ${shares} peers (got ${peer_count})"
}

require_cmd docker
require_cmd jq
require_cmd kustomize

cd "${POC_DIR}"

local_compose_json="${TMP_DIR}/compose-local.json"
$DC config --format json >"${local_compose_json}"

local_nexus_threshold="$(compose_env_value "${local_compose_json}" "spike-nexus" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
local_nexus_shares="$(compose_env_value "${local_compose_json}" "spike-nexus" "SPIKE_NEXUS_SHAMIR_SHARES")"
local_nexus_peers="$(compose_env_value "${local_compose_json}" "spike-nexus" "SPIKE_NEXUS_KEEPER_PEERS")"
local_bootstrap_threshold="$(compose_env_value "${local_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
local_bootstrap_shares="$(compose_env_value "${local_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_SHAMIR_SHARES")"
local_bootstrap_peers="$(compose_env_value "${local_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_KEEPER_PEERS")"

assert_demo_profile "docker-compose.yml spike-nexus" "${local_nexus_threshold}" "${local_nexus_shares}" "${local_nexus_peers}"
assert_demo_profile "docker-compose.yml spike-bootstrap" "${local_bootstrap_threshold}" "${local_bootstrap_shares}" "${local_bootstrap_peers}"

prod_compose_json="${TMP_DIR}/compose-prod-intent.json"
STRICT_UPSTREAM_URL="https://strict-upstream.example.com/mcp" \
APPROVAL_SIGNING_KEY="compose-production-intent-approval-key-material-32chars" \
ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/ops/sa/gateway-admin" \
UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/tools/sa/mcp-tool" \
KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/data/sa/keydb" \
$DC --profile strict \
  --env-file config/compose-production-intent.env \
  -f deploy/compose/docker-compose.strict.yml \
  -f deploy/compose/docker-compose.prod-intent.yml \
  config --format json >"${prod_compose_json}"

for service in spike-keeper-1 spike-keeper-2 spike-keeper-3; do
  jq -e --arg svc "${service}" '.services[$svc]' "${prod_compose_json}" >/dev/null \
    || fail "production-intent compose: missing ${service} service"
done

prod_nexus_threshold="$(compose_env_value "${prod_compose_json}" "spike-nexus" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
prod_nexus_shares="$(compose_env_value "${prod_compose_json}" "spike-nexus" "SPIKE_NEXUS_SHAMIR_SHARES")"
prod_nexus_peers="$(compose_env_value "${prod_compose_json}" "spike-nexus" "SPIKE_NEXUS_KEEPER_PEERS")"
prod_bootstrap_threshold="$(compose_env_value "${prod_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
prod_bootstrap_shares="$(compose_env_value "${prod_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_SHAMIR_SHARES")"
prod_bootstrap_peers="$(compose_env_value "${prod_compose_json}" "spike-bootstrap" "SPIKE_NEXUS_KEEPER_PEERS")"

assert_release_profile "docker-compose.prod-intent.yml spike-nexus" "${prod_nexus_threshold}" "${prod_nexus_shares}" "${prod_nexus_peers}"
assert_release_profile "docker-compose.prod-intent.yml spike-bootstrap" "${prod_bootstrap_threshold}" "${prod_bootstrap_shares}" "${prod_bootstrap_peers}"

eks_release_yaml="${TMP_DIR}/spike-release.yaml"
kustomize build deploy/terraform/spike >"${eks_release_yaml}"

for keeper_name in spike-keeper-1 spike-keeper-2 spike-keeper-3; do
  grep -Eq "name:[[:space:]]*${keeper_name}([[:space:]]|$)" "${eks_release_yaml}" \
    || fail "deploy/terraform/spike: missing ${keeper_name} in rendered release manifests"
done

eks_release_doc="$(render_doc ConfigMap spike-nexus-config "${eks_release_yaml}")"
[[ -n "${eks_release_doc}" ]] || fail "deploy/terraform/spike: rendered spike-nexus-config ConfigMap not found"
eks_release_threshold="$(doc_key_value "${eks_release_doc}" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
eks_release_shares="$(doc_key_value "${eks_release_doc}" "SPIKE_NEXUS_SHAMIR_SHARES")"
eks_release_peers="$(doc_key_value "${eks_release_doc}" "SPIKE_NEXUS_KEEPER_PEERS")"

assert_release_profile "deploy/terraform/spike ConfigMap" "${eks_release_threshold}" "${eks_release_shares}" "${eks_release_peers}"

eks_release_bootstrap_threshold="$(job_env_value "deploy/terraform/spike/bootstrap-job.yaml" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
eks_release_bootstrap_shares="$(job_env_value "deploy/terraform/spike/bootstrap-job.yaml" "SPIKE_NEXUS_SHAMIR_SHARES")"
eks_release_bootstrap_peers="$(job_env_value "deploy/terraform/spike/bootstrap-job.yaml" "SPIKE_NEXUS_KEEPER_PEERS")"
assert_release_profile "deploy/terraform/spike/bootstrap-job.yaml" "${eks_release_bootstrap_threshold}" "${eks_release_bootstrap_shares}" "${eks_release_bootstrap_peers}"

local_overlay_yaml="${TMP_DIR}/spike-local.yaml"
kustomize build deploy/terraform/overlays/local >"${local_overlay_yaml}"

local_overlay_doc="$(render_doc ConfigMap spike-nexus-config "${local_overlay_yaml}")"
[[ -n "${local_overlay_doc}" ]] || fail "deploy/terraform/overlays/local: rendered spike-nexus-config ConfigMap not found"
local_overlay_threshold="$(doc_key_value "${local_overlay_doc}" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
local_overlay_shares="$(doc_key_value "${local_overlay_doc}" "SPIKE_NEXUS_SHAMIR_SHARES")"
local_overlay_peers="$(doc_key_value "${local_overlay_doc}" "SPIKE_NEXUS_KEEPER_PEERS")"
assert_demo_profile "deploy/terraform/overlays/local spike-nexus-config" "${local_overlay_threshold}" "${local_overlay_shares}" "${local_overlay_peers}"

if grep -Eq 'name:[[:space:]]*spike-keeper-(2|3)([[:space:]]|$)' "${local_overlay_yaml}"; then
  fail "deploy/terraform/overlays/local: release-only keeper-2/3 resources must not render in the local overlay"
fi

local_bootstrap_threshold="$(job_env_value "deploy/terraform/overlays/local/spike-bootstrap-job.yaml" "SPIKE_NEXUS_SHAMIR_THRESHOLD")"
local_bootstrap_shares="$(job_env_value "deploy/terraform/overlays/local/spike-bootstrap-job.yaml" "SPIKE_NEXUS_SHAMIR_SHARES")"
local_bootstrap_peers="$(job_env_value "deploy/terraform/overlays/local/spike-bootstrap-job.yaml" "SPIKE_NEXUS_KEEPER_PEERS")"
assert_demo_profile "deploy/terraform/overlays/local/spike-bootstrap-job.yaml" "${local_bootstrap_threshold}" "${local_bootstrap_shares}" "${local_bootstrap_peers}"

echo "[PASS] docker-compose.yml keeps demo bootstrap at 1-of-1 with a single keeper peer"
echo "[PASS] docker-compose.prod-intent.yml renders multi-share recovery with three keeper peers"
echo "[PASS] deploy/terraform/spike renders release-facing multi-share recovery with keeper-1/2/3"
echo "[PASS] deploy/terraform/overlays/local keeps the demo/local exception isolated at 1-of-1"
