#!/usr/bin/env bash
# Compose Supply Chain Verifier (RFA-545e.4)
#
# Fails fast if any third-party (non-build) service image is:
# - using a floating :latest tag, or
# - not digest-pinned (@sha256:...).
#
# Local build images (services with `build:`) are allowed to be unpinned.
#
# RFA-yprx extension:
# - also verifies Dockerfile FROM references for compose build services are
#   digest-pinned (@sha256:...), ignoring local stage aliases.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"

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

# bash 3.2 compatible "array contains" helper
array_contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "${item}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

append_unique() {
  local value="$1"
  local arr_name="$2"
  local current=()
  # bash 3.2 compatible indirection for arrays
  eval "current=(\"\${${arr_name}[@]-}\")"
  if ! array_contains "${value}" "${current[@]:-}"; then
    eval "${arr_name}+=(\"\${value}\")"
  fi
}

normalize_path() {
  local input="$1"
  local dir base
  dir="$(dirname "${input}")"
  base="$(basename "${input}")"
  if cd "${dir}" >/dev/null 2>&1; then
    printf '%s/%s\n' "$(pwd)" "${base}"
    return 0
  fi
  # Fallback (still useful in error output if dir does not exist)
  printf '%s\n' "${input}"
}

build_images="$(echo "${cfg_json}" | jq -r '
  .services
  | to_entries[]
  | select((.value.build // null) != null)
  | (.value.image // empty)
' | sort -u)"

missing_digest=()
latest_tag=()
dockerfile_from_unpinned=()
dockerfiles=()

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

# Collect Dockerfiles for compose build services.
while IFS=$'\t' read -r context dockerfile; do
  if [[ -z "${context}" || "${context}" == "null" ]]; then
    context="."
  fi
  if [[ -z "${dockerfile}" || "${dockerfile}" == "null" ]]; then
    dockerfile="Dockerfile"
  fi

  local_context="${context}"
  if [[ "${local_context}" != /* ]]; then
    local_context="${ROOT_DIR}/${local_context}"
  fi

  df_path="${dockerfile}"
  if [[ "${df_path}" != /* ]]; then
    df_path="${local_context}/${df_path}"
  fi

  append_unique "$(normalize_path "${df_path}")" dockerfiles
done < <(echo "${cfg_json}" | jq -r '
  .services
  | to_entries[]
  | select((.value.build // null) != null)
  | if (.value.build | type) == "string" then
      [ .value.build, "Dockerfile" ]
    else
      [ (.value.build.context // "."), (.value.build.dockerfile // "Dockerfile") ]
    end
  | @tsv
')

# Optional extra Dockerfile paths (used by deterministic negative-path tests).
# Delimiter: ":".
if [[ -n "${COMPOSE_VERIFY_EXTRA_DOCKERFILES:-}" ]]; then
  old_ifs="${IFS}"
  IFS=':'
  for extra_df in ${COMPOSE_VERIFY_EXTRA_DOCKERFILES}; do
    [[ -z "${extra_df}" ]] && continue
    if [[ "${extra_df}" != /* ]]; then
      extra_df="${ROOT_DIR}/${extra_df}"
    fi
    append_unique "$(normalize_path "${extra_df}")" dockerfiles
  done
  IFS="${old_ifs}"
fi

check_dockerfile_froms() {
  local dockerfile_path="$1"
  local line line_no from_match rest from_ref alias_idx alias_name
  local stage_aliases=()
  local tokens=()

  if [[ ! -f "${dockerfile_path}" ]]; then
    dockerfile_from_unpinned+=("${dockerfile_path}:missing-file")
    return
  fi

  line_no=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))

    # Strip trailing comments for parsing.
    line="${line%%#*}"

    shopt -s nocasematch
    if [[ ! "${line}" =~ ^[[:space:]]*FROM[[:space:]]+(.+)$ ]]; then
      shopt -u nocasematch
      continue
    fi
    rest="${BASH_REMATCH[1]}"
    shopt -u nocasematch

    # shellcheck disable=SC2206
    tokens=(${rest})
    if (( ${#tokens[@]} == 0 )); then
      continue
    fi

    # Optional --platform flag appears immediately after FROM.
    if [[ "${tokens[0]}" == --platform=* ]]; then
      if (( ${#tokens[@]} < 2 )); then
        continue
      fi
      from_ref="${tokens[1]}"
      alias_idx=2
    else
      from_ref="${tokens[0]}"
      alias_idx=1
    fi

    # Ignore internal stage references (e.g., FROM builder).
    if array_contains "${from_ref}" "${stage_aliases[@]:-}"; then
      continue
    fi

    # Ignore scratch base image.
    if [[ "${from_ref}" == "scratch" ]]; then
      continue
    fi

    # Best effort: skip fully variable-driven references.
    if [[ "${from_ref}" == '$'* || "${from_ref}" == *'${'* ]]; then
      continue
    fi

    # Third-party external image reference must be digest-pinned.
    if [[ "${from_ref}" != *@sha256:* ]]; then
      dockerfile_from_unpinned+=("${dockerfile_path}:${line_no}:${from_ref}")
    fi

    # Track stage alias if present: FROM <img> AS <alias>
    if (( ${#tokens[@]} > alias_idx + 1 )); then
      shopt -s nocasematch
      if [[ "${tokens[$alias_idx]}" == "as" ]]; then
        alias_name="${tokens[$((alias_idx + 1))]}"
        if [[ -n "${alias_name}" ]]; then
          append_unique "${alias_name}" stage_aliases
        fi
      fi
      shopt -u nocasematch
    fi
  done < "${dockerfile_path}"
}

for dockerfile_path in "${dockerfiles[@]:-}"; do
  check_dockerfile_froms "${dockerfile_path}"
done

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

if (( ${#dockerfile_from_unpinned[@]} > 0 )); then
  echo "[FAIL] Found Dockerfile FROM references without digest pinning (@sha256:...):" >&2
  printf '  - %s\n' "${dockerfile_from_unpinned[@]}" >&2
  exit 1
fi
pass "All compose Dockerfile FROM references are digest-pinned (@sha256:...)"

echo ""
echo "compose-verify: PASS"
