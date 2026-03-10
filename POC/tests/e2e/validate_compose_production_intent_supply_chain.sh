#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
PREFLIGHT_SCRIPT="${POC_DIR}/scripts/compose-production-intent-preflight.sh"
BASE_ENV_FILE="${POC_DIR}/config/compose-production-intent.env"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd docker
require_cmd jq
[[ -x "${PREFLIGHT_SCRIPT}" ]] || fail "preflight script missing or not executable: ${PREFLIGHT_SCRIPT}"
[[ -f "${BASE_ENV_FILE}" ]] || fail "base env lock file missing: ${BASE_ENV_FILE}"

echo "[INFO] Validating compose production-intent supply-chain gate"

"${PREFLIGHT_SCRIPT}"

tmp_env="$(mktemp)"
trap 'rm -f "${tmp_env}"' EXIT
cp "${BASE_ENV_FILE}" "${tmp_env}"

# Deterministic negative check: a non-digest image ref must fail preflight.
perl -0pi -e 's/^PROD_GATEWAY_IMAGE=.*/PROD_GATEWAY_IMAGE=ghcr.io\/precinct-dev\/precinct\/mcp-security-gateway:latest/m' "${tmp_env}"

if COMPOSE_PROD_ENV_FILE="${tmp_env}" "${PREFLIGHT_SCRIPT}" >/tmp/compose-prod-intent-negative.log 2>&1; then
  cat /tmp/compose-prod-intent-negative.log
  fail "preflight should fail when production image is not digest-pinned"
fi

echo "[PASS] Negative-path check succeeded (non-digest production image rejected)"
echo "[PASS] Compose production-intent supply-chain validation passed"
