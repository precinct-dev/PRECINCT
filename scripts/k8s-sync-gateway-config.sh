#!/usr/bin/env bash
set -euo pipefail

# k8s-sync-gateway-config.sh -- Detect and fix drift between the canonical
# config/ directory (used by Docker Compose) and the K8s overlay copy
# (infra/eks/overlays/local/gateway-config/).
#
# The K8s overlay uses a configMapGenerator that requires files to be local
# to the overlay directory. This script ensures those copies stay in sync
# with the canonical source in config/.
#
# Run modes:
#   --check   Exit non-zero if any files are out of sync (CI use)
#   --sync    Copy canonical files to the K8s overlay (default)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

COMPOSE_CONFIG="${POC_ROOT}/config"
K8S_OVERLAY="${POC_ROOT}/infra/eks/overlays/local/gateway-config"

MODE="${1:---sync}"

# Map of K8s overlay files to their canonical source.
# Format: "overlay_filename:source_path" (relative to POC_ROOT)
# Files that are K8s-specific (no Compose equivalent) are excluded.
SYNC_MAP=(
  "mcp_policy.rego:config/opa/mcp_policy.rego"
  "mcp_policy.rego.sig:config/opa/mcp_policy.rego.sig"
  "ui_policy.rego:config/opa/ui_policy.rego"
  "ui_policy.rego.sig:config/opa/ui_policy.rego.sig"
  "ui_csp_policy.rego:config/opa/ui_csp_policy.rego"
  "ui_csp_policy.rego.sig:config/opa/ui_csp_policy.rego.sig"
  "exfiltration.rego:config/opa/exfiltration.rego"
  "exfiltration.rego.sig:config/opa/exfiltration.rego.sig"
  "context_policy.rego:config/opa/context_policy.rego"
  "context_policy.rego.sig:config/opa/context_policy.rego.sig"
  "principal_policy.rego:config/opa/principal_policy.rego"
  "principal_policy.rego.sig:config/opa/principal_policy.rego.sig"
  "tool_grants.yaml:config/opa/tool_grants.yaml"
  "tool_grants.yaml.sig:config/opa/tool_grants.yaml.sig"
  "ui_capability_grants.yaml:config/opa/ui_capability_grants.yaml"
  "ui_capability_grants.yaml.sig:config/opa/ui_capability_grants.yaml.sig"
  "tool-registry.yaml:config/tool-registry.yaml"
  "tool-registry.yaml.sig:config/tool-registry.yaml.sig"
  "capability-registry-v2.yaml:config/capability-registry-v2.yaml"
  "model-provider-catalog.v2.yaml:config/model-provider-catalog.v2.yaml"
  "model-provider-catalog.v2.yaml.sig:config/model-provider-catalog.v2.yaml.sig"
  "attestation-ed25519.pub:config/attestation-ed25519.pub"
  "guard-artifact.bin:config/guard-artifact.bin"
  "guard-artifact.bin.sig:config/guard-artifact.bin.sig"
  "destinations.yaml:config/destinations.yaml"
  "risk_thresholds.yaml:config/risk_thresholds.yaml"
)

# K8s-specific files (no canonical source, managed independently):
#   extensions-demo-k8s.yaml  -- K8s uses cluster DNS for content-scanner

drift_found=0

for entry in "${SYNC_MAP[@]}"; do
  overlay_file="${entry%%:*}"
  source_rel="${entry##*:}"
  source_path="${POC_ROOT}/${source_rel}"
  target_path="${K8S_OVERLAY}/${overlay_file}"

  if [ ! -f "$source_path" ]; then
    echo "WARNING: canonical source missing: ${source_rel}"
    continue
  fi

  if [ ! -f "$target_path" ]; then
    echo "DRIFT: ${overlay_file} missing in K8s overlay (source: ${source_rel})"
    drift_found=1
    if [ "$MODE" = "--sync" ]; then
      cp "$source_path" "$target_path"
      echo "  -> copied"
    fi
    continue
  fi

  if ! diff -q "$source_path" "$target_path" >/dev/null 2>&1; then
    echo "DRIFT: ${overlay_file} differs from ${source_rel}"
    drift_found=1
    if [ "$MODE" = "--sync" ]; then
      cp "$source_path" "$target_path"
      echo "  -> synced"
    fi
  fi
done

if [ "$drift_found" -eq 0 ]; then
  echo "K8s gateway config in sync with canonical source."
else
  if [ "$MODE" = "--check" ]; then
    echo ""
    echo "ERROR: K8s gateway config is out of sync."
    echo "Run: make k8s-sync-config  (or: bash scripts/k8s-sync-gateway-config.sh --sync)"
    exit 1
  else
    echo ""
    echo "K8s gateway config synced."
  fi
fi
