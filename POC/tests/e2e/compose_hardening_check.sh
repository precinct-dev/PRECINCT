#!/usr/bin/env bash
# Compose Hardening Check (RFA-545e.3)
#
# Validates a least-privilege baseline for key services in Docker Compose:
# - no-new-privileges
# - drop all Linux capabilities
# - (selected services) run as non-root
#
# This is a runtime check using `docker inspect` so we don't silently regress.

set -euo pipefail

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

# Container names are pinned via `container_name:` in POC/docker-compose.yml.
hardened=(
  "mcp-security-gateway"
  "mock-mcp-server"
  "mock-guard-model"
  "spike-nexus"
  "spike-keeper-1"
)

non_root_required=(
  "mcp-security-gateway"
  "mock-mcp-server"
  "mock-guard-model"
)

inspect() {
  docker inspect "$1" 2>/dev/null | jq '.[0]'
}

has_no_new_privileges() {
  # Prefer HostConfig.NoNewPrivileges when present; fall back to SecurityOpt string.
  # Different Docker versions surface this differently.
  local name="$1"
  local cfg
  cfg="$(inspect "${name}")" || return 1

  local nn
  nn="$(echo "${cfg}" | jq -r '(.HostConfig.NoNewPrivileges // empty)')"
  if [ "${nn}" = "true" ]; then
    return 0
  fi

  echo "${cfg}" | jq -e '(.HostConfig.SecurityOpt // []) | any(. == "no-new-privileges:true")' >/dev/null
}

has_cap_drop_all() {
  local name="$1"
  local cfg
  cfg="$(inspect "${name}")" || return 1

  echo "${cfg}" | jq -e '(.HostConfig.CapDrop // []) | any(. == "ALL")' >/dev/null
}

has_no_cap_add() {
  local name="$1"
  local cfg
  cfg="$(inspect "${name}")" || return 1

  # CapAdd may be null or [] when none are added.
  echo "${cfg}" | jq -e '(.HostConfig.CapAdd == null) or ((.HostConfig.CapAdd | length) == 0)' >/dev/null
}

is_non_root_user() {
  local name="$1"
  local cfg user
  cfg="$(inspect "${name}")" || return 1
  user="$(echo "${cfg}" | jq -r '.Config.User // ""')"

  # Accept non-empty, and reject common root encodings.
  if [ -z "${user}" ]; then
    return 1
  fi
  if [ "${user}" = "0" ] || [ "${user}" = "0:0" ] || [ "${user}" = "root" ]; then
    return 1
  fi
  return 0
}

pass "Runtime hardening checks (docker inspect)"

for c in "${hardened[@]}"; do
  if ! docker inspect "${c}" >/dev/null 2>&1; then
    fail "container not found (stack must be up): ${c}"
  fi

  if ! has_no_new_privileges "${c}"; then
    fail "${c}: no-new-privileges is not enabled"
  fi
  if ! has_cap_drop_all "${c}"; then
    fail "${c}: CapDrop does not include ALL"
  fi
  if ! has_no_cap_add "${c}"; then
    fail "${c}: CapAdd is set (expected none)"
  fi

  pass "${c}: no-new-privileges + cap_drop=ALL validated"
done

for c in "${non_root_required[@]}"; do
  if ! is_non_root_user "${c}"; then
    fail "${c}: container is running as root (or user is unspecified)"
  fi
  pass "${c}: non-root user validated"
done

echo ""
echo "compose_hardening_check: PASS"

