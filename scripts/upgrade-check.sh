#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSIONS_FILE="${ROOT_DIR}/config/versions.yaml"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
PHOENIX_COMPOSE_FILE="${ROOT_DIR}/docker-compose.phoenix.yml"
COMPLIANCE_REQS="${ROOT_DIR}/tools/compliance/requirements.txt"
COMPLIANCE_VENV_PY="${ROOT_DIR}/tools/compliance/.venv/bin/python3"

FORMAT="table"

usage() {
  cat <<'EOF'
Usage:
  scripts/upgrade-check.sh [--format table|json]

Outputs current vs latest versions for the stack, plus Go module and Python dependency update summaries.

Test-only (stable, no network):
  scripts/upgrade-check.sh --_test_compare <a> <b>
  scripts/upgrade-check.sh --_test_extract_images <compose-yaml>
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--json" ]]; then
  FORMAT="json"
  shift
fi

if [[ "${1:-}" == "--format" ]]; then
  FORMAT="${2:-}"
  shift 2
fi

if [[ "${1:-}" == "--_test_compare" ]]; then
  a="${2:-}"
  b="${3:-}"
  if [[ -z "$a" || -z "$b" ]]; then
    echo "ERROR: --_test_compare requires 2 args" >&2
    exit 2
  fi
  a="${a#v}"
  b="${b#v}"
  if [[ "$a" == "$b" ]]; then
    echo "eq"
    exit 0
  fi
  # sort -V works well for dotted numeric versions.
  if [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]; then
    echo "lt"
  else
    echo "gt"
  fi
  exit 0
fi

if [[ "${1:-}" == "--_test_extract_images" ]]; then
  f="${2:-}"
  if [[ -z "$f" ]]; then
    echo "ERROR: --_test_extract_images requires a file path" >&2
    exit 2
  fi
  if [[ ! -f "$f" ]]; then
    echo "ERROR: file not found: $f" >&2
    exit 2
  fi
  grep -nE '^[[:space:]]*image:[[:space:]]*' "$f" \
    | sed -E 's/^[^:]+:[[:space:]]*image:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^["'\'']//; s/["'\'']$//' \
    | awk 'NF{print}'
  exit 0
fi

if [[ -n "${1:-}" ]]; then
  echo "ERROR: unknown arguments: $*" >&2
  usage >&2
  exit 2
fi

if [[ "$FORMAT" != "table" && "$FORMAT" != "json" ]]; then
  echo "ERROR: --format must be 'table' or 'json' (got: $FORMAT)" >&2
  exit 2
fi

if [[ ! -f "$VERSIONS_FILE" ]]; then
  echo "ERROR: missing version manifest: $VERSIONS_FILE" >&2
  exit 1
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }

strip_quotes() {
  local s="$1"
  s="${s#\"}"; s="${s%\"}"
  s="${s#\'}"; s="${s%\'}"
  printf '%s' "$s"
}

canonical_image_no_tag() {
  # Input: "repo/name" or "ghcr.io/org/name". Output: same, no tag/digest.
  local image="$1"
  image="${image%@*}"
  # Strip :tag but preserve registry :port by only considering the last path segment.
  local last="${image##*/}"
  if [[ "$last" == *:* ]]; then
    image="${image%:*}"
  fi
  printf '%s' "$image"
}

registry_host_and_repo() {
  # Input: image without tag/digest (e.g., ghcr.io/spiffe/spire-server, eqalpha/keydb)
  local image="$1"
  local first="${image%%/*}"
  local rest="${image#*/}"

  if [[ "$image" == "$first" ]]; then
    # no slash; treat as docker hub library
    echo "docker.io library/${image}"
    return 0
  fi

  if [[ "$first" == *.* || "$first" == *:* || "$first" == "localhost" ]]; then
    echo "$first $rest"
  else
    echo "docker.io $image"
  fi
}

fetch_tags_registry_v2() {
  # Best-effort: prints tags (one per line) to stdout. Returns 0 even on partial failure.
  local image_no_tag="$1"
  local host repo
  read -r host repo < <(registry_host_and_repo "$image_no_tag")

  if ! have_cmd curl; then
    return 1
  fi
  if ! have_cmd python3; then
    return 1
  fi

  local tags_url token_url token api_host
  api_host="$host"
  if [[ "$host" == "docker.io" ]]; then
    api_host="registry-1.docker.io"
    token_url="https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull"
  elif [[ "$host" == "ghcr.io" ]]; then
    token_url="https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull"
  else
    token_url=""
  fi

  token=""
  if [[ -n "$token_url" ]]; then
    token="$(curl -fsSL "$token_url" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)"
  fi

  tags_url="https://${api_host}/v2/${repo}/tags/list?n=1000"

  if [[ -n "$token" ]]; then
    curl -fsSL -H "Authorization: Bearer ${token}" "$tags_url" 2>/dev/null \
      | python3 -c 'import json,sys; print("\n".join((json.load(sys.stdin).get("tags") or [])))' 2>/dev/null || true
    return 0
  fi

  # Some registries allow anonymous tag listing; try without auth.
  curl -fsSL "$tags_url" 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join((json.load(sys.stdin).get("tags") or [])))' 2>/dev/null || true
  return 0
}

fetch_tags_skopeo() {
  local image_no_tag="$1"
  if ! have_cmd skopeo; then
    return 1
  fi
  if ! have_cmd python3; then
    return 1
  fi

  # skopeo understands docker://docker.io/<repo> and docker://ghcr.io/<repo>
  skopeo list-tags "docker://${image_no_tag}" 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("Tags") or []))' 2>/dev/null || true
  return 0
}

select_latest_semver() {
  # Reads tags (one per line) on stdin, outputs best "latest" tag.
  # Preference: highest stable semver tag; fallback to "latest" if present.
  local tags semver best
  tags="$(cat || true)"
  semver="$(printf '%s\n' "$tags" \
    | sed -E 's/^v//' \
    | grep -E '^[0-9]+(\.[0-9]+){1,3}$' \
    | grep -Ev '-' \
    | sort -V \
    | tail -n 1 \
    || true)"

  if [[ -n "$semver" ]]; then
    echo "$semver"
    return 0
  fi

  if printf '%s\n' "$tags" | grep -qx 'latest' >/dev/null 2>&1; then
    echo "latest"
    return 0
  fi

  best="$(printf '%s\n' "$tags" | head -n 1 || true)"
  echo "$best"
}

compare_versions() {
  # echoes: lt|eq|gt (a compared to b)
  local a="${1#v}"
  local b="${2#v}"
  if [[ "$a" == "$b" ]]; then
    echo "eq"
    return 0
  fi
  if [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]; then
    echo "lt"
  else
    echo "gt"
  fi
}

declare -a COMPONENTS=()
declare -A COMP_IMAGE=()
declare -A COMP_VERSION=()
declare -A COMP_PINNED=()

parse_versions_yaml() {
  local in_components=0 comp="" val
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue
    if [[ "$line" =~ ^components:[[:space:]]*$ ]]; then
      in_components=1
      continue
    fi
    if [[ $in_components -eq 0 ]]; then
      continue
    fi
    # Stop on next top-level section.
    if [[ "$line" =~ ^[a-zA-Z0-9_-]+: && ! "$line" =~ ^components: ]]; then
      break
    fi
    if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):[[:space:]]*$ ]]; then
      comp="${BASH_REMATCH[1]}"
      COMPONENTS+=("$comp")
      continue
    fi
    if [[ -z "$comp" ]]; then
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]{4}image:[[:space:]]*(.+)$ ]]; then
      val="$(strip_quotes "${BASH_REMATCH[1]}")"
      COMP_IMAGE["$comp"]="$val"
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]{4}version:[[:space:]]*(.+)$ ]]; then
      val="$(strip_quotes "${BASH_REMATCH[1]}")"
      COMP_VERSION["$comp"]="$val"
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]{4}pinned:[[:space:]]*(.+)$ ]]; then
      val="$(strip_quotes "${BASH_REMATCH[1]}")"
      COMP_PINNED["$comp"]="$val"
      continue
    fi
  done < "$VERSIONS_FILE"
}

parse_versions_yaml

generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

extract_images_from_compose() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  grep -nE '^[[:space:]]*image:[[:space:]]*' "$f" \
    | sed -E 's/^[^:]+:[[:space:]]*image:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^["'\'']//; s/["'\'']$//' \
    | awk 'NF{print}'
}

declare -a DISCOVERED_IMAGES=()
if [[ -f "$COMPOSE_FILE" ]]; then
  while IFS= read -r img; do
    [[ -n "$img" ]] && DISCOVERED_IMAGES+=("$img")
  done < <(extract_images_from_compose "$COMPOSE_FILE")
fi
if [[ -f "$PHOENIX_COMPOSE_FILE" ]]; then
  while IFS= read -r img; do
    [[ -n "$img" ]] && DISCOVERED_IMAGES+=("$img")
  done < <(extract_images_from_compose "$PHOENIX_COMPOSE_FILE")
fi

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))' </dev/stdin
}

declare -a JSON_COMPONENTS=()

emit_component_json() {
  local name="$1" image="$2" current="$3" latest="$4" pinned="$5" status="$6" notes="$7"
  # Build a small JSON object as a string (keeps this bash-only).
  local obj
  obj="{\"component\":$(printf '%s' "$name" | json_escape),\"current\":$(printf '%s' "$current" | json_escape),\"latest\":$(printf '%s' "$latest" | json_escape),\"status\":$(printf '%s' "$status" | json_escape)"
  obj+=",\"pinned\":${pinned}"
  if [[ -n "$image" ]]; then
    obj+=",\"image\":$(printf '%s' "$image" | json_escape)"
  fi
  if [[ -n "$notes" ]]; then
    obj+=",\"notes\":$(printf '%s' "$notes" | json_escape)"
  fi
  obj+="}"
  JSON_COMPONENTS+=("$obj")
}

if [[ "$FORMAT" == "table" ]]; then
  printf '%-16s %-12s %-12s %s\n' "COMPONENT" "CURRENT" "LATEST" "STATUS"
fi

for comp in "${COMPONENTS[@]}"; do
  image="${COMP_IMAGE[$comp]:-}"
  current="${COMP_VERSION[$comp]:-}"
  pinned_raw="${COMP_PINNED[$comp]:-false}"
  pinned="false"
  if [[ "$pinned_raw" == "true" ]]; then
    pinned="true"
  fi

  image_no_tag="$(canonical_image_no_tag "$image")"

  tags_method="registry_v2"
  tags="$(fetch_tags_skopeo "$image_no_tag" || true)"
  if [[ -n "$tags" ]]; then
    tags_method="skopeo"
  else
    tags="$(fetch_tags_registry_v2 "$image_no_tag" || true)"
  fi

  latest="$(printf '%s\n' "$tags" | select_latest_semver)"
  status="UNKNOWN"
  notes=""

  if [[ -z "$latest" ]]; then
    latest="unknown"
    status="UNKNOWN"
    notes="tag listing failed"
  elif [[ "$current" == "latest" ]]; then
    status="FLOATING"
    notes="current=latest (floating); tags via ${tags_method}"
  else
    cmp="$(compare_versions "$current" "$latest")"
    if [[ "$cmp" == "lt" ]]; then
      status="UPDATE AVAILABLE"
      if [[ "$pinned" == "true" ]]; then
        status="UPDATE AVAILABLE (pinned -- skip)"
      fi
      notes="tags via ${tags_method}"
    else
      status="UP TO DATE"
      notes="tags via ${tags_method}"
    fi
  fi

  if [[ "$FORMAT" == "table" ]]; then
    printf '%-16s %-12s %-12s %s\n' "$comp" "$current" "$latest" "$status"
  fi
  emit_component_json "$comp" "$image_no_tag" "$current" "$latest" "$pinned" "$status" "$notes"
done

# Go modules (summary count)
go_status="UNKNOWN"
go_notes=""
if have_cmd go; then
  # go list -m -u all prints: module current [update]
  if out="$(cd "$ROOT_DIR" && go list -m -u all 2>/dev/null)"; then
    count="$(printf '%s\n' "$out" | grep -c '\[' || true)"
    go_status="${count} updates available"
    go_notes="via go list -m -u all"
  else
    go_status="UNKNOWN"
    go_notes="go list -m -u all failed"
  fi
else
  go_notes="go not installed"
fi

if [[ "$FORMAT" == "table" ]]; then
  printf '%-16s %-12s %-12s %s\n' "go-modules" "--" "--" "$go_status"
fi
emit_component_json "go-modules" "" "--" "--" "false" "$go_status" "$go_notes"

# Python deps (compliance venv only)
py_status="UNKNOWN"
py_notes=""
if [[ -f "$COMPLIANCE_REQS" ]]; then
  if [[ -x "$COMPLIANCE_VENV_PY" ]]; then
    if have_cmd python3; then
      # pip JSON output is easiest to count reliably.
      if out="$("$COMPLIANCE_VENV_PY" -m pip list --outdated --format=json 2>/dev/null)"; then
        count="$(printf '%s' "$out" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data))' 2>/dev/null || echo "unknown")"
        if [[ "$count" == "unknown" ]]; then
          py_status="UNKNOWN"
          py_notes="pip output parse failed"
        else
          py_status="${count} updates available"
          py_notes="via pip list --outdated (tools/compliance/.venv)"
        fi
      else
        py_status="UNKNOWN"
        py_notes="pip list --outdated failed"
      fi
    else
      py_notes="python3 not installed"
    fi
  else
    py_notes="missing tools/compliance/.venv (run make compliance-report once to bootstrap)"
  fi
else
  py_notes="missing tools/compliance/requirements.txt"
fi

if [[ "$FORMAT" == "table" ]]; then
  printf '%-16s %-12s %-12s %s\n' "python-deps" "--" "--" "$py_status"
fi
emit_component_json "python-deps" "" "--" "--" "false" "$py_status" "$py_notes"

# OPA policies (manual)
if [[ "$FORMAT" == "table" ]]; then
  printf '%-16s %-12s %-12s %s\n' "opa-policies" "config/opa" "--" "MANUAL"
fi
emit_component_json "opa-policies" "" "config/opa" "--" "true" "MANUAL" "version tracked in config/opa/ (manual)"

if [[ "$FORMAT" == "json" ]]; then
  # Join array elements with commas.
  joined=""
  for obj in "${JSON_COMPONENTS[@]}"; do
    if [[ -z "$joined" ]]; then
      joined="$obj"
    else
      joined="${joined},${obj}"
    fi
  done

  # JSON: include compose-discovered images so the script demonstrably reads compose files.
  images_joined=""
  if [[ ${#DISCOVERED_IMAGES[@]} -gt 0 ]]; then
    # Unique while preserving order.
    declare -A seen=()
    for img in "${DISCOVERED_IMAGES[@]}"; do
      if [[ -z "${seen[$img]:-}" ]]; then
        seen["$img"]=1
        if [[ -z "$images_joined" ]]; then
          images_joined="$(printf '%s' "$img" | json_escape)"
        else
          images_joined="${images_joined},$(printf '%s' "$img" | json_escape)"
        fi
      fi
    done
  fi

  printf '{'
  printf '"generated_at":%s,' "$(printf '%s' "$generated_at" | json_escape)"
  printf '"discovered_images":[%s],' "$images_joined"
  printf '"components":[%s]' "$joined"
  printf '}\n'
fi
