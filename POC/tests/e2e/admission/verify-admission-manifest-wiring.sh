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

check_constraint_namespaces() {
  local doc="$1"
  local label="$2"
  [ -n "$doc" ] || fail "missing $label constraint manifest"
  echo "$doc" | grep -Eq '^[[:space:]]*-[[:space:]]*gateway[[:space:]]*$' || fail "$label must include namespace gateway"
  echo "$doc" | grep -Eq '^[[:space:]]*-[[:space:]]*tools[[:space:]]*$' || fail "$label must include namespace tools"
  for stale in mcp-gateway mcp-servers policy-system; do
    if echo "$doc" | grep -Eq "^[[:space:]]*-[[:space:]]*${stale}[[:space:]]*$"; then
      fail "$label contains stale namespace ${stale}"
    fi
  done
}

check_enforcement_action() {
  local doc="$1"
  local label="$2"
  local expected="$3"
  [ -n "$doc" ] || fail "missing ${label} manifest for enforcementAction check"
  echo "$doc" | grep -Eq "enforcementAction:[[:space:]]*${expected}" \
    || fail "${label} must set enforcementAction=${expected}"
}

check_namespace_include_label() {
  local doc="$1"
  local ns="$2"
  [ -n "$doc" ] || fail "missing Namespace/${ns} manifest in rendered overlay"
  echo "$doc" | grep -Eq 'policy\.sigstore\.dev/include:[[:space:]]*"true"' || fail "Namespace/${ns} missing policy.sigstore.dev/include=true"
}

check_keyless_identity_scope() {
  local doc="$1"
  local line=""
  [ -n "$doc" ] || fail "missing ClusterImagePolicy/require-cosign-signatures manifest"
  line="$(echo "$doc" | grep -E 'subjectRegExp:' || true)"
  [ -n "$line" ] || fail "missing keyless subjectRegExp in ClusterImagePolicy"
  echo "$line" | grep -F 'RamXX/agentic_reference_architecture/.github/workflows/' >/dev/null \
    || fail "keyless subjectRegExp is not repository/workflow scoped"
  echo "$line" | grep -F '@refs/heads/' >/dev/null \
    || fail "keyless subjectRegExp is missing branch scoping"
  if echo "$line" | grep -Eq 'https://github\.com/\.\*'; then
    fail "keyless subjectRegExp still uses global github wildcard"
  fi
}

main() {
  require_bin kustomize

  local overlays=(dev staging prod)
  for overlay in "${overlays[@]}"; do
    local rendered="/tmp/precinct-admission-${overlay}.yaml"
    info "Building overlay: ${overlay}"
    kustomize build "infra/eks/overlays/${overlay}" >"${rendered}"

    local sig_doc
    sig_doc="$(extract_doc "${rendered}" "RequireImageSignature" "enforce-image-signature")"
    check_constraint_namespaces "$sig_doc" "RequireImageSignature/enforce-image-signature"
    check_enforcement_action "$sig_doc" "RequireImageSignature/enforce-image-signature" "deny"

    local digest_doc
    digest_doc="$(extract_doc "${rendered}" "RequireImageDigest" "enforce-image-digest")"
    check_constraint_namespaces "$digest_doc" "RequireImageDigest/enforce-image-digest"
    check_enforcement_action "$digest_doc" "RequireImageDigest/enforce-image-digest" "deny"

    local gateway_ns
    gateway_ns="$(extract_doc "${rendered}" "Namespace" "gateway")"
    check_namespace_include_label "$gateway_ns" "gateway"

    local tools_ns
    tools_ns="$(extract_doc "${rendered}" "Namespace" "tools")"
    check_namespace_include_label "$tools_ns" "tools"

    local cip_doc
    cip_doc="$(extract_doc "${rendered}" "ClusterImagePolicy" "require-cosign-signatures")"
    check_keyless_identity_scope "$cip_doc"
  done

  local local_rendered="/tmp/precinct-admission-local.yaml"
  info "Building overlay: local"
  kustomize build "infra/eks/overlays/local" >"${local_rendered}"

  local local_sig_doc
  local_sig_doc="$(extract_doc "${local_rendered}" "RequireImageSignature" "enforce-image-signature")"
  check_enforcement_action "$local_sig_doc" "local RequireImageSignature/enforce-image-signature" "dryrun"

  local local_digest_doc
  local_digest_doc="$(extract_doc "${local_rendered}" "RequireImageDigest" "enforce-image-digest")"
  check_enforcement_action "$local_digest_doc" "local RequireImageDigest/enforce-image-digest" "dryrun"

  info "Admission manifest wiring checks passed for dev/staging/prod + local relaxation."
}

main "$@"
