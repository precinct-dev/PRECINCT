#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

info() {
  echo "[INFO] $*"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required binary: $1"
}

extract_doc() {
  local file="$1"
  local kind="$2"
  local name="$3"
  awk -v kind="$kind" -v name="$name" '
    BEGIN { RS="---" }
    $0 ~ ("kind:[[:space:]]*" kind "([[:space:]]|$)") &&
    $0 ~ ("name:[[:space:]]*" name "([[:space:]]|$)") {
      print
    }
  ' "$file"
}

load_list_after_key() {
  local doc="$1"
  local key="$2"
  echo "$doc" | awk -v key="$key" '
    $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" {
      in_list=1
      key_indent=match($0, /[^ ]/) - 1
      next
    }
    in_list && /^[[:space:]]*$/ { next }
    in_list && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/"/, "", line)
      print line
      next
    }
    in_list && (match($0, /[^ ]/) - 1) <= key_indent { exit }
  '
}

image_is_exempt() {
  local image="$1"
  shift
  local pattern
  for pattern in "$@"; do
    case "$image" in
      $pattern)
        return 0
        ;;
    esac
  done
  return 1
}

collect_images_for_namespace() {
  local file="$1"
  local namespace="$2"
  awk -v namespace="$namespace" '
    BEGIN { RS="---"; FS="\n" }
    {
      kind=""
      objns=""
      for (i = 1; i <= NF; i++) {
        line=$i
        if (line ~ /^[[:space:]]*kind:[[:space:]]*/) {
          sub(/^[[:space:]]*kind:[[:space:]]*/, "", line)
          kind=line
        }
        if (line ~ /^[[:space:]]*namespace:[[:space:]]*/) {
          sub(/^[[:space:]]*namespace:[[:space:]]*/, "", line)
          objns=line
        }
      }

      if (objns != namespace) {
        next
      }
      if (kind !~ /^(Pod|Deployment|ReplicaSet|StatefulSet|DaemonSet|Job|CronJob)$/) {
        next
      }

      for (i = 1; i <= NF; i++) {
        line=$i
        if (line ~ /^[[:space:]]*image:[[:space:]]*/) {
          sub(/^[[:space:]]*image:[[:space:]]*/, "", line)
          gsub(/"/, "", line)
          print line
        }
      }
    }
  ' "$file"
}

main() {
  require_bin kustomize

  local overlays=()
  if [ "$#" -gt 0 ]; then
    overlays=("$@")
  elif [ -n "${OVERLAYS:-}" ]; then
    read -r -a overlays <<<"${OVERLAYS}"
  else
    overlays=(staging prod)
  fi

  local -a allowed_exemptions=(
    "registry.k8s.io/pause*"
    "602401143452.dkr.ecr.*.amazonaws.com/eks/pause*"
  )

  local overlay
  for overlay in "${overlays[@]}"; do
    local rendered
    rendered="$(mktemp "/tmp/precinct-overlay-digest-${overlay}.XXXXXX")"
    info "Building overlay: ${overlay}"
    kustomize build "deploy/terraform/overlays/${overlay}" >"${rendered}"

    local digest_doc
    digest_doc="$(extract_doc "${rendered}" "RequireImageDigest" "enforce-image-digest")"
    [ -n "${digest_doc}" ] || fail "missing RequireImageDigest/enforce-image-digest in ${overlay}"

    mapfile -t namespaces < <(load_list_after_key "${digest_doc}" "namespaces")
    [ "${#namespaces[@]}" -gt 0 ] || fail "missing digest-policy namespaces in ${overlay}"

    mapfile -t exemptions < <(load_list_after_key "${digest_doc}" "exemptImages")
    [ "${#exemptions[@]}" -gt 0 ] || fail "missing digest-policy exemptions in ${overlay}"

    local exemption
    for exemption in "${exemptions[@]}"; do
      case "${exemption}" in
        registry.k8s.io/pause*|602401143452.dkr.ecr.*.amazonaws.com/eks/pause*)
          ;;
        *)
          fail "${overlay} adds non-platform digest exemption: ${exemption}"
          ;;
      esac
    done

    local namespace
    for namespace in "${namespaces[@]}"; do
      mapfile -t images < <(collect_images_for_namespace "${rendered}" "${namespace}")
      [ "${#images[@]}" -gt 0 ] || fail "no workload images found for namespace ${namespace} in ${overlay}"

      local image
      for image in "${images[@]}"; do
        if [[ "${image}" == *@sha256:* ]]; then
          continue
        fi
        if image_is_exempt "${image}" "${allowed_exemptions[@]}"; then
          continue
        fi
        fail "${overlay} namespace ${namespace} renders non-digest image: ${image}"
      done
    done

    info "Overlay ${overlay} renders digest-pinned gateway/tools workloads and keeps only platform-managed exemptions."
  done

  info "Rendered overlay digest policy validation passed."
}

main "$@"
