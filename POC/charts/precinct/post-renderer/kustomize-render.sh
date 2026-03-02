#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Kustomize Post-Renderer for Helm
#
# This script bridges Helm's template output with kustomize's overlay system.
# Helm calls this script as a post-renderer:
#   1. Helm renders templates and pipes the output to this script's stdin
#   2. This script writes the rendered kustomization.yaml to a temp directory
#   3. kustomize build runs against the overlay referenced in the kustomization
#   4. The final manifests are written to stdout for kubectl apply
#
# Usage:
#   helm install precinct charts/precinct/ \
#     --post-renderer charts/precinct/post-renderer/kustomize-render.sh
# ------------------------------------------------------------------------------
set -euo pipefail

# Create a temporary working directory
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# Read Helm's rendered output from stdin
cat > "${TMPDIR}/helm-output.yaml"

# Extract the kustomization.yaml from Helm output
# The rendered template contains a Kustomization resource that references
# the correct overlay based on values.global.environment
KUST_DIR="${TMPDIR}/kustomize"
mkdir -p "${KUST_DIR}"

# Parse the overlay path from the rendered kustomization
# Look for the resources line that points to the overlay directory
OVERLAY_PATH=$(grep -A1 'resources:' "${TMPDIR}/helm-output.yaml" | tail -1 | sed 's/^[[:space:]]*- //' | sed 's/^[[:space:]]*//')

if [ -z "${OVERLAY_PATH}" ]; then
  echo "ERROR: Could not extract overlay path from Helm output" >&2
  exit 1
fi

# Resolve the overlay path relative to the chart directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OVERLAY_ABS="${CHART_DIR}/${OVERLAY_PATH}"

if [ ! -d "${OVERLAY_ABS}" ]; then
  echo "ERROR: Overlay directory not found: ${OVERLAY_ABS}" >&2
  exit 1
fi

# Run kustomize build against the resolved overlay
kustomize build "${OVERLAY_ABS}"
