#!/usr/bin/env bash
# Compose Bootstrap Verifier (RFA-545e.5)
#
# Ensures one-shot init containers completed successfully so Compose runs are
# deterministic and failures aren't silently missed.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

pass() {
  echo "[PASS] $1"
}

if ! command -v docker >/dev/null 2>&1; then
  fail "docker not found"
fi
if ! command -v jq >/dev/null 2>&1; then
  fail "jq not found"
fi
if [[ ! -f "${COMPOSE_FILE}" ]]; then
  fail "compose file not found: ${COMPOSE_FILE}"
fi

# Required one-shot services. We only enforce the ones that exist in this compose file.
required=(
  "spire-token-generator"
  "spire-entry-registrar"
  "spike-bootstrap"
  "spike-secret-seeder"
)

cfg_json="$(docker compose -f "${COMPOSE_FILE}" config --format json)"
present_services="$(echo "${cfg_json}" | jq -r '.services | keys[]' | sort -u)"

max_wait_sec="${COMPOSE_BOOTSTRAP_VERIFY_TIMEOUT_SEC:-180}"
interval_sec="${COMPOSE_BOOTSTRAP_VERIFY_INTERVAL_SEC:-2}"
deadline="$(( $(date +%s) + max_wait_sec ))"

while true; do
  ps_jsonl="$(docker compose -f "${COMPOSE_FILE}" ps -a --format json)"
  ps_json="$(echo "${ps_jsonl}" | jq -s '.')"

  missing=()
  pending=()
  bad=()

  for svc in "${required[@]}"; do
    if ! printf '%s\n' "${present_services}" | grep -Fxq -- "${svc}"; then
      # Not part of this compose stack (or gated behind profiles).
      continue
    fi

    row="$(echo "${ps_json}" | jq -c --arg s "${svc}" 'map(select(.Service == $s)) | .[0] // empty')"
    if [[ -z "${row}" ]]; then
      missing+=("${svc}")
      continue
    fi

    state="$(echo "${row}" | jq -r '.State // ""')"
    exit_code="$(echo "${row}" | jq -r '.ExitCode // -1')"

    if [[ "${state}" == "exited" && "${exit_code}" == "0" ]]; then
      continue
    fi

    # If it exited non-zero, fail immediately.
    if [[ "${state}" == "exited" && "${exit_code}" != "0" ]]; then
      bad+=("${svc}\tstate=${state}\texit=${exit_code}")
      continue
    fi

    # Otherwise it's still starting/running/created; allow a short bounded wait.
    pending+=("${svc}\tstate=${state}\texit=${exit_code}")
  done

  if (( ${#missing[@]} > 0 )); then
    echo "[FAIL] Missing expected one-shot containers (stack must be up):" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    exit 1
  fi

  if (( ${#bad[@]} > 0 )); then
    echo "[FAIL] One-shot bootstrap containers did not complete successfully:" >&2
    printf '  - %b\n' "${bad[@]}" >&2
    exit 1
  fi

  if (( ${#pending[@]} == 0 )); then
    break
  fi

  if (( $(date +%s) >= deadline )); then
    echo "[FAIL] One-shot bootstrap containers did not complete within ${max_wait_sec}s:" >&2
    printf '  - %b\n' "${pending[@]}" >&2
    exit 1
  fi

  sleep "${interval_sec}"
done

pass "One-shot bootstrap containers completed successfully"
echo ""
echo "compose-bootstrap-verify: PASS"
