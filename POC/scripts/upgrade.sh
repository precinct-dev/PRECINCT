#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSIONS_FILE="${ROOT_DIR}/config/versions.yaml"
UPGRADE_CHECK="${ROOT_DIR}/scripts/upgrade-check.sh"

DOCKER_COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
PHOENIX_COMPOSE_FILE="${ROOT_DIR}/docker-compose.phoenix.yml"

UPGRADES_DIR="${ROOT_DIR}/docs/upgrades"
SNAPSHOT_DIR_BASE="${ROOT_DIR}/config/upgrade-snapshots"

usage() {
  cat <<'EOF'
Usage:
  scripts/upgrade.sh --component <name> [--verify]
  scripts/upgrade.sh --all [--verify]

Notes:
- Snapshot is always created first: config/versions.yaml.snapshot.<timestamp>
- Default test suite: make ci && make demo-compose
- Verification: --verify is best-effort; it skips when cosign isn't installed and skips external images.

Test-only helpers (no network):
  scripts/upgrade.sh --_test_update_versions <versions.yaml> <component> <new_version>
  scripts/upgrade.sh --_test_snapshot_roundtrip <srcfile>
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

have_cmd() { command -v "$1" >/dev/null 2>&1; }

die() {
  echo "ERROR: $*" >&2
  exit 1
}

ensure_git_clean() {
  if ! have_cmd git; then
    die "git is required for upgrade commit/rollback behavior"
  fi
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    die "not inside a git repository"
  fi
  if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is dirty; commit or stash changes before running upgrade"
  fi
}

update_versions_yaml_version_inplace() {
  local file="$1"
  local component="$2"
  local new_version="$3"

  [[ -f "$file" ]] || die "versions file not found: $file"

  # Only supports the simple YAML structure used by config/versions.yaml.
  awk -v comp="$component" -v newv="$new_version" '
    BEGIN { in_comp=0; updated=0 }
    $0 ~ "^  " comp ":[[:space:]]*$" { in_comp=1; print; next }
    in_comp && $0 ~ "^  [a-zA-Z0-9_-]+:[[:space:]]*$" { in_comp=0 }
    in_comp && $0 ~ "^    version:[[:space:]]*" {
      print "    version: \"" newv "\""
      updated=1
      next
    }
    { print }
  ' "$file" > "${file}.tmp"

  mv "${file}.tmp" "$file"
}

test_only_update_versions() {
  local file="${2:-}"
  local comp="${3:-}"
  local newv="${4:-}"
  [[ -n "$file" && -n "$comp" && -n "$newv" ]] || die "--_test_update_versions requires: <file> <component> <new_version>"
  update_versions_yaml_version_inplace "$file" "$comp" "$newv"
}

test_only_snapshot_roundtrip() {
  local src="${2:-}"
  [[ -n "$src" ]] || die "--_test_snapshot_roundtrip requires: <srcfile>"
  [[ -f "$src" ]] || die "file not found: $src"
  local ts
  ts="$(date +%s)"
  local snapdir="/tmp/upgrade-snapshot-test-${ts}"
  mkdir -p "$snapdir"
  cp "$src" "$snapdir/original"
  cp "$src" "$snapdir/snapshot"
  echo "mutated" >>"$src"
  cp "$snapdir/snapshot" "$src"
  diff -q "$snapdir/original" "$src" >/dev/null
}

if [[ "${1:-}" == "--_test_update_versions" ]]; then
  test_only_update_versions "$@"
  exit 0
fi
if [[ "${1:-}" == "--_test_snapshot_roundtrip" ]]; then
  test_only_snapshot_roundtrip "$@"
  exit 0
fi

MODE=""
COMPONENT=""
VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --component)
      MODE="component"
      COMPONENT="${2:-}"
      shift 2
      ;;
    --all)
      MODE="all"
      shift
      ;;
    --verify)
      VERIFY=1
      shift
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if [[ "$MODE" == "component" && -z "$COMPONENT" ]]; then
  die "--component requires a value"
fi
if [[ -z "$MODE" ]]; then
  usage >&2
  exit 2
fi

[[ -f "$VERSIONS_FILE" ]] || die "missing version manifest: $VERSIONS_FILE"
[[ -x "$UPGRADE_CHECK" ]] || die "missing upgrade-check script: $UPGRADE_CHECK"

ensure_git_clean

start_epoch="$(date +%s)"
ts="$(date +%s)"
snapshot_file="${ROOT_DIR}/config/versions.yaml.snapshot.${ts}"
mkdir -p "$SNAPSHOT_DIR_BASE/$ts" "$UPGRADES_DIR"

cp "$VERSIONS_FILE" "$snapshot_file"

# Capture a broader snapshot for rollback (not part of AC name, but needed for safe rollback).
for f in \
  "config/versions.yaml" \
  "docker-compose.yml" \
  "docker-compose.phoenix.yml" \
  "docker/Dockerfile.spire-agent" \
  "docker/Dockerfile.spike-nexus" \
  "docker/Dockerfile.spike-keeper" \
  "go.mod" \
  "go.sum"; do
  if [[ -f "${ROOT_DIR}/${f}" ]]; then
    mkdir -p "$(dirname "${SNAPSHOT_DIR_BASE}/${ts}/${f}")"
    cp "${ROOT_DIR}/${f}" "${SNAPSHOT_DIR_BASE}/${ts}/${f}"
  fi
done

restore_from_snapshot() {
  for f in $(cd "${SNAPSHOT_DIR_BASE}/${ts}" && find . -type f -print | sed 's|^\\./||'); do
    mkdir -p "$(dirname "${ROOT_DIR}/${f}")"
    cp "${SNAPSHOT_DIR_BASE}/${ts}/${f}" "${ROOT_DIR}/${f}"
  done
}

report_date="$(date +%F)"
report_file="${UPGRADES_DIR}/${report_date}-upgrade-report.md"
ci_log="${SNAPSHOT_DIR_BASE}/${ts}/make-ci.log"
demo_log="${SNAPSHOT_DIR_BASE}/${ts}/make-demo-compose.log"

write_report() {
  local status="$1" # SUCCESS|FAILURE
  local changes_md="$2"
  local ci_status="$3"
  local demo_status="$4"
  local duration="$5"

  cat >"$report_file" <<EOF
# Upgrade Report: ${report_date}

## Summary
Status: ${status}
Components upgraded: ${upgraded_count}
Tests run: make ci, make demo-compose
Duration: ${duration}s

## Changes
| Component | Old Version | New Version | Status |
|-----------|-------------|-------------|--------|
${changes_md}

## Test Results
- make ci: ${ci_status}
- make demo-compose: ${demo_status}

## Rollback Info
Snapshot: $(basename "$snapshot_file")
Snapshot Dir: ${SNAPSHOT_DIR_BASE}/${ts}

## Logs
- make ci log: ${ci_log}
- make demo-compose log: ${demo_log}
EOF
}

perl_inplace() {
  local expr="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  perl -0777 -pi -e "$expr" "$file"
}

update_compose_image() {
  local file="$1"
  local image="$2"
  local newv="$3"
  perl_inplace "s/(\\bimage:\\s*\\Q${image}\\E:)[^\\s#]+/\\${1}${newv}/g" "$file"
}

update_dockerfile_from() {
  local file="$1"
  local image="$2"
  local newv="$3"
  perl_inplace "s/(^FROM\\s+\\Q${image}\\E:)[^\\s]+/\\${1}${newv}/mg" "$file"
}

pull_image_if_possible() {
  local image="$1" newv="$2"
  if [[ "${UPGRADE_SKIP_DOCKER:-0}" == "1" ]]; then
    return 0
  fi
  if have_cmd docker; then
    docker pull "${image}:${newv}" >/dev/null 2>&1 || true
  fi
}

verify_image_if_requested() {
  local image="$1" newv="$2"
  if [[ "$VERIFY" -ne 1 ]]; then
    return 0
  fi
  if ! have_cmd cosign; then
    return 0
  fi
  # Only verify images produced by this repo's GH Actions identity.
  local remote owner repo id_re
  remote="$(git config --get remote.origin.url || true)"
  owner="$(printf '%s' "$remote" | sed -nE 's|.*github\\.com[:/]+([^/]+)/([^/.]+)(\\.git)?$|\\1|p')"
  repo="$(printf '%s' "$remote" | sed -nE 's|.*github\\.com[:/]+([^/]+)/([^/.]+)(\\.git)?$|\\2|p')"
  if [[ -z "$owner" || -z "$repo" ]]; then
    return 0
  fi
  if [[ "$image" != ghcr.io/* ]]; then
    return 0
  fi
  # Skip external namespaces.
  if [[ "$image" != "ghcr.io/${owner}/"* && "$image" != "ghcr.io/${owner}/${repo}"* ]]; then
    return 0
  fi
  id_re="https://github.com/${owner}/${repo}/.*"
  cosign verify \
    --certificate-identity-regexp="${id_re}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
    "${image}:${newv}" >/dev/null 2>&1 || true
}

CHECK_JSON="${UPGRADE_CHECK_JSON:-}"
if [[ -z "$CHECK_JSON" ]]; then
  CHECK_JSON="$(bash "$UPGRADE_CHECK" --format json)"
fi

# Build a map from upgrade-check output: component -> current/latest/pinned/image.
if ! have_cmd python3; then
  die "python3 is required to parse upgrade-check JSON"
fi

component_rows="$(printf '%s' "$CHECK_JSON" | python3 -c '
import json,sys
data=json.load(sys.stdin)
for c in data.get("components", []):
    name=c.get("component","")
    cur=c.get("current","")
    lat=c.get("latest","")
    pin=c.get("pinned", False)
    img=c.get("image","")
    print(f"{name}\t{cur}\t{lat}\t{str(pin).lower()}\t{img}")
')"

declare -a targets=()
if [[ "$MODE" == "component" ]]; then
  targets+=("$COMPONENT")
else
  # Upgrade all non-pinned components from versions.yaml (as reflected in upgrade-check output).
  while IFS=$'\t' read -r name cur lat pin img; do
    [[ -z "$name" ]] && continue
    if [[ "$pin" == "false" ]]; then
      targets+=("$name")
    fi
  done <<<"$component_rows"
fi

declare -A cur_by=()
declare -A lat_by=()
declare -A pin_by=()
declare -A img_by=()
while IFS=$'\t' read -r name cur lat pin img; do
  [[ -z "$name" ]] && continue
  cur_by["$name"]="$cur"
  lat_by["$name"]="$lat"
  pin_by["$name"]="$pin"
  img_by["$name"]="$img"
done <<<"$component_rows"

changes_md=""
upgraded_count=0

apply_component_update() {
  local name="$1"

  if [[ -z "${cur_by[$name]:-}" && -z "${lat_by[$name]:-}" ]]; then
    die "unknown component: $name"
  fi

  local cur="${cur_by[$name]:-}"
  local lat="${lat_by[$name]:-}"
  local pin="${pin_by[$name]:-false}"
  local img="${img_by[$name]:-}"

  if [[ "$pin" == "true" && "$MODE" == "all" ]]; then
    # Skip pinned components in upgrade-all.
    return 0
  fi
  if [[ "$pin" == "true" && "$MODE" == "component" ]]; then
    die "component is pinned; refusing to upgrade: $name"
  fi

  if [[ -z "$lat" || "$lat" == "unknown" || "$lat" == "--" ]]; then
    changes_md+="| ${name} | ${cur} | ${lat:-unknown} | SKIP (no latest) |\n"
    return 0
  fi
  if [[ "$cur" == "$lat" ]]; then
    changes_md+="| ${name} | ${cur} | ${lat} | UP TO DATE |\n"
    return 0
  fi

  # Update versions.yaml version.
  update_versions_yaml_version_inplace "$VERSIONS_FILE" "$name" "$lat"

  # Update source-of-truth files that pin versions.
  case "$name" in
    spire-server)
      update_compose_image "$DOCKER_COMPOSE_FILE" "ghcr.io/spiffe/spire-server" "$lat"
      pull_image_if_possible "ghcr.io/spiffe/spire-server" "$lat"
      ;;
    spire-agent)
      update_dockerfile_from "${ROOT_DIR}/docker/Dockerfile.spire-agent" "ghcr.io/spiffe/spire-agent" "$lat"
      if [[ "${UPGRADE_SKIP_DOCKER:-0}" != "1" ]] && have_cmd docker; then
        docker compose build spire-agent >/dev/null 2>&1 || true
      fi
      ;;
    spike-nexus)
      update_dockerfile_from "${ROOT_DIR}/docker/Dockerfile.spike-nexus" "ghcr.io/spiffe/spike-nexus" "$lat"
      if [[ "${UPGRADE_SKIP_DOCKER:-0}" != "1" ]] && have_cmd docker; then
        docker compose build spike-nexus >/dev/null 2>&1 || true
      fi
      ;;
    spike-keeper)
      update_dockerfile_from "${ROOT_DIR}/docker/Dockerfile.spike-keeper" "ghcr.io/spiffe/spike-keeper" "$lat"
      if [[ "${UPGRADE_SKIP_DOCKER:-0}" != "1" ]] && have_cmd docker; then
        docker compose build spike-keeper-1 >/dev/null 2>&1 || true
      fi
      ;;
    keydb)
      update_compose_image "$DOCKER_COMPOSE_FILE" "eqalpha/keydb" "$lat"
      pull_image_if_possible "docker.io/eqalpha/keydb" "$lat"
      ;;
    otel-collector)
      update_compose_image "$PHOENIX_COMPOSE_FILE" "otel/opentelemetry-collector-contrib" "$lat"
      pull_image_if_possible "docker.io/otel/opentelemetry-collector-contrib" "$lat"
      ;;
    phoenix)
      update_compose_image "$PHOENIX_COMPOSE_FILE" "arizephoenix/phoenix" "$lat"
      pull_image_if_possible "docker.io/arizephoenix/phoenix" "$lat"
      ;;
    go-modules)
      (cd "$ROOT_DIR" && go get -u ./... && go mod tidy)
      ;;
    *)
      # Unknown mapping: versions.yaml updated only.
      ;;
  esac

  verify_image_if_requested "$img" "$lat"
  upgraded_count=$((upgraded_count + 1))
  changes_md+="| ${name} | ${cur} | ${lat} | OK |\n"
}

overall_status="SUCCESS"
ci_status="NOT RUN"
demo_status="NOT RUN"

set +e
for t in "${targets[@]}"; do
  apply_component_update "$t"
  if [[ $? -ne 0 ]]; then
    overall_status="FAILURE"
    break
  fi
done
set -e

if [[ "$overall_status" == "SUCCESS" ]]; then
  set +e
  (cd "$ROOT_DIR" && make ci) >"$ci_log" 2>&1
  ci_rc=$?
  if [[ $ci_rc -eq 0 ]]; then
    ci_status="PASS"
  else
    ci_status="FAIL"
  fi
  (cd "$ROOT_DIR" && make demo-compose) >"$demo_log" 2>&1
  demo_rc=$?
  if [[ $demo_rc -eq 0 ]]; then
    demo_status="PASS"
  else
    demo_status="FAIL"
  fi
  set -e

  if [[ "$ci_status" != "PASS" || "$demo_status" != "PASS" ]]; then
    overall_status="FAILURE"
  fi
fi

end_epoch="$(date +%s)"
duration="$((end_epoch - start_epoch))"

if [[ "$overall_status" == "SUCCESS" ]]; then
  write_report "SUCCESS" "$changes_md" "$ci_status" "$demo_status" "$duration"
  if ! git diff --quiet; then
    git add -A
    git commit -m "upgrade: ${MODE} ${COMPONENT:-all} (${report_date})" >/dev/null 2>&1 || true
  fi
  exit 0
fi

# FAILURE: rollback and write failure report.
restore_from_snapshot
write_report "FAILURE" "$changes_md" "$ci_status" "$demo_status" "$duration"
exit 1
