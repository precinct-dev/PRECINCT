#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
POC_DIR="${ROOT_DIR}"
BASE_ENV_FILE="${POC_DIR}/config/compose-production-intent.env"
tmp_dir=""

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

info() {
  echo "[INFO] $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

check_compose_cfg() {
  local cfg="$1"

  jq -e '.services["mcp-security-gateway"]' "${cfg}" >/dev/null || {
    echo "gateway service missing"
    return 1
  }

  local network_mode
  network_mode="$(jq -r '.services["mcp-security-gateway"].network_mode // ""' "${cfg}")"
  if [ -n "${network_mode}" ]; then
    echo "gateway must not set network_mode (found: ${network_mode})"
    return 1
  fi

  local expected_networks=(agentic-net tool-plane secrets-plane data-plane phoenix-net)
  for net in "${expected_networks[@]}"; do
    jq -e --arg n "${net}" '.services["mcp-security-gateway"].networks | has($n)' "${cfg}" >/dev/null || {
      echo "gateway missing required network: ${net}"
      return 1
    }
  done

  mapfile -t attached_networks < <(jq -r '.services["mcp-security-gateway"].networks | keys[]' "${cfg}")
  for net in "${attached_networks[@]}"; do
    case "${net}" in
      agentic-net|tool-plane|secrets-plane|data-plane|phoenix-net) ;;
      *)
        echo "gateway attached to unexpected network: ${net}"
        return 1
        ;;
    esac
  done

  for net in agentic-net tool-plane secrets-plane data-plane; do
    local internal
    internal="$(jq -r --arg n "${net}" '.networks[$n].internal // false' "${cfg}")"
    if [ "${internal}" != "true" ]; then
      echo "network ${net} must be internal=true (got ${internal})"
      return 1
    fi
  done

  local phoenix_external
  phoenix_external="$(jq -r '.networks["phoenix-net"].external // false' "${cfg}")"
  if [ "${phoenix_external}" != "true" ]; then
    echo "phoenix-net must remain external=true for observability wiring"
    return 1
  fi

  local profile mode spiffe mediation projection upstream
  profile="$(jq -r '.services["mcp-security-gateway"].environment.ENFORCEMENT_PROFILE // ""' "${cfg}")"
  mode="$(jq -r '.services["mcp-security-gateway"].environment.MCP_TRANSPORT_MODE // ""' "${cfg}")"
  spiffe="$(jq -r '.services["mcp-security-gateway"].environment.SPIFFE_MODE // ""' "${cfg}")"
  mediation="$(jq -r '.services["mcp-security-gateway"].environment.ENFORCE_MODEL_MEDIATION_GATE // "" | ascii_downcase' "${cfg}")"
  projection="$(jq -r '.services["mcp-security-gateway"].environment.MODEL_POLICY_INTENT_PREPEND_ENABLED // "" | ascii_downcase' "${cfg}")"
  upstream="$(jq -r '.services["mcp-security-gateway"].environment.UPSTREAM_URL // ""' "${cfg}")"

  [ "${profile}" = "prod_standard" ] || {
    echo "ENFORCEMENT_PROFILE must be prod_standard (got ${profile})"
    return 1
  }
  [ "${mode}" = "mcp" ] || {
    echo "MCP_TRANSPORT_MODE must be mcp (got ${mode})"
    return 1
  }
  [ "${spiffe}" = "prod" ] || {
    echo "SPIFFE_MODE must be prod (got ${spiffe})"
    return 1
  }
  [ "${mediation}" = "true" ] || {
    echo "ENFORCE_MODEL_MEDIATION_GATE must be true in strict compose profile"
    return 1
  }
  [ "${projection}" = "true" ] || {
    echo "MODEL_POLICY_INTENT_PREPEND_ENABLED must be true in strict compose profile"
    return 1
  }
  [[ "${upstream}" =~ ^https:// ]] || {
    echo "UPSTREAM_URL must be https:// in strict compose profile (got ${upstream})"
    return 1
  }
}

main() {
  require_cmd docker
  require_cmd jq
  [ -f "${BASE_ENV_FILE}" ] || fail "base env lock file missing: ${BASE_ENV_FILE}"

  local cfg_json bad_cfg
  tmp_dir="$(mktemp -d)"
  trap '[ -n "${tmp_dir:-}" ] && rm -rf "${tmp_dir}"' EXIT
  cfg_json="${tmp_dir}/compose-strict-prod-intent.json"
  bad_cfg="${tmp_dir}/compose-strict-prod-intent.bad.json"

  export STRICT_UPSTREAM_URL="https://strict-upstream.example.com/mcp"
  export APPROVAL_SIGNING_KEY="compose-approval-signing-key-material-at-least-32"
  export UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/tools/sa/mcp-tool"
  export KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/data/sa/keydb"
  export ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/admin/sa/operator"

  info "Rendering strict+production-intent compose config"
  docker compose --profile strict \
    --env-file "${BASE_ENV_FILE}" \
    -f "${ROOT_DIR}/deploy/compose/docker-compose.yml" \
    -f "${ROOT_DIR}/deploy/compose/docker-compose.strict.yml" \
    -f "${ROOT_DIR}/deploy/compose/docker-compose.prod-intent.yml" \
    config --format json >"${cfg_json}"

  info "Validating compose egress control posture"
  check_compose_cfg "${cfg_json}" || fail "compose strict production-intent egress checks failed"

  info "Running deterministic negative-path check (host networking must be rejected)"
  jq '.services["mcp-security-gateway"].network_mode = "host"' "${cfg_json}" >"${bad_cfg}"
  if check_compose_cfg "${bad_cfg}" >/dev/null 2>&1; then
    fail "negative-path check failed: validator accepted gateway network_mode=host"
  fi

  echo "[PASS] Compose strict production-intent egress validation passed"
}

main "$@"
