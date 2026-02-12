#!/usr/bin/env bash
# Compose Supply Chain Verifier (RFA-545e.4)
#
# Fails fast if any third-party (non-build) service image is:
# - using a floating :latest tag, or
# - not digest-pinned (@sha256:...).
#
# Local build images (services with `build:`) are allowed to be unpinned.

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

cfg_json="$(docker compose -f "${COMPOSE_FILE}" config --format json)"

build_images="$(echo "${cfg_json}" | jq -r '
  .services
  | to_entries[]
  | select((.value.build // null) != null)
  | (.value.image // empty)
' | sort -u)"

missing_digest=()
latest_tag=()

while IFS=$'\t' read -r svc has_build image; do
  # Skip local builds (allowed to be unpinned)
  if [[ "${has_build}" == "true" ]]; then
    continue
  fi

  if [[ -z "${image}" || "${image}" == "null" ]]; then
    # Unusual but not our concern here.
    continue
  fi

  # Some services intentionally reuse a locally-built image but do not define
  # `build:` themselves (e.g., init containers). Treat these as local.
  if [[ -n "${build_images}" ]] && printf '%s\n' "${build_images}" | grep -Fxq -- "${image}"; then
    continue
  fi

  # Check for :latest tag (only in the tag portion, not registry host:port)
  img_no_digest="${image%@*}"
  last_seg="${img_no_digest##*/}"
  if [[ "${last_seg}" == *:latest ]]; then
    latest_tag+=("${svc}=${image}")
  fi

  # Require digest pinning for third-party images
  if [[ "${image}" != *@sha256:* ]]; then
    missing_digest+=("${svc}=${image}")
  fi
done < <(echo "${cfg_json}" | jq -r '
  .services
  | to_entries[]
  | [
      .key,
      (if (.value.build // null) == null then "false" else "true" end),
      (.value.image // "null")
    ]
  | @tsv
')

if (( ${#latest_tag[@]} > 0 )); then
  echo "[FAIL] Found third-party services using :latest:" >&2
  printf '  - %s\n' "${latest_tag[@]}" >&2
  exit 1
fi
pass "No third-party services use :latest"

if (( ${#missing_digest[@]} > 0 )); then
  echo "[FAIL] Found third-party services without digest pinning (@sha256:...):" >&2
  printf '  - %s\n' "${missing_digest[@]}" >&2
  exit 1
fi
pass "All third-party services are digest-pinned (@sha256:...)"

echo ""
echo "compose-verify: PASS"
