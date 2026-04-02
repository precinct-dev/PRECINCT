#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

info() {
  echo "[INFO] $*"
}

main() {
  local gateway_policy="deploy/terraform/policies/gateway-allow.yaml"
  local tool_policy="deploy/terraform/policies/mcp-server-allow.yaml"
  local gateway_ns="deploy/terraform/gateway/gateway-namespace.yaml"

  [ -f "$gateway_policy" ] || fail "missing $gateway_policy"
  [ -f "$tool_policy" ] || fail "missing $tool_policy"
  [ -f "$gateway_ns" ] || fail "missing $gateway_ns"

  info "Checking gateway ingress is allowlisted (not world-open)..."
  grep -Eq 'networking\.agentic\.io/gateway-ingress-allowed:[[:space:]]*"true"' "$gateway_policy" \
    || fail "gateway ingress policy missing allowlist namespace label selector"
  if awk 'BEGIN{RS="---"} /kind:[[:space:]]*NetworkPolicy/ && /name:[[:space:]]*gateway-allow-ingress/ {print}' "$gateway_policy" | \
      grep -Eq 'ingress:[[:space:]]*$[[:space:]]*-[[:space:]]*ports:'; then
    fail "gateway ingress policy still has a world-open ingress rule (ports without from)"
  fi

  info "Checking gateway namespace carries ingress allowlist label..."
  grep -Eq 'networking\.agentic\.io/gateway-ingress-allowed:[[:space:]]*"true"' "$gateway_ns" \
    || fail "gateway namespace missing networking.agentic.io/gateway-ingress-allowed=true"

  info "Checking tool egress denies blanket internet and allows private ranges only..."
  if grep -Eq 'cidr:[[:space:]]*0\.0\.0\.0/0' "$tool_policy"; then
    fail "tool egress still contains 0.0.0.0/0"
  fi
  for cidr in "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"; do
    grep -Eq "cidr:[[:space:]]*${cidr}" "$tool_policy" \
      || fail "tool egress missing allowlisted private range ${cidr}"
  done

  info "Checking gateway egress does not include broad external HTTPS allow..."
  if awk 'BEGIN{RS="---"} /kind:[[:space:]]*NetworkPolicy/ && /name:[[:space:]]*gateway-allow-egress/ {print}' "$gateway_policy" | \
      grep -Eq '(^|[[:space:]])port:[[:space:]]*443([[:space:]]|$)'; then
    fail "gateway egress still contains broad port 443 allow"
  fi

  info "NetworkPolicy manifest wiring checks passed."
}

main "$@"
