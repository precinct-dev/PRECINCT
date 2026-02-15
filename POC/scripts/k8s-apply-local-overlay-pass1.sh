#!/usr/bin/env bash
set -euo pipefail

# Pass 1 apply for local overlay:
# apply all base resources and ConstraintTemplates, but skip Gatekeeper Constraint
# instances until pass 2 after templates are established.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

command -v kustomize >/dev/null 2>&1 || {
  echo "ERROR: kustomize is required"
  exit 1
}
command -v kubectl >/dev/null 2>&1 || {
  echo "ERROR: kubectl is required"
  exit 1
}

kustomize build "${POC_ROOT}/infra/eks/overlays/local" \
  | awk '
      function flush_doc() {
        if (doc == "") return
        if (!skip_doc) {
          printf "%s", doc
        }
        doc = ""
        skip_doc = 0
        kind_captured = 0
      }
      {
        if ($0 == "---") {
          flush_doc()
          doc = "---\n"
          next
        }
        if (doc == "") {
          doc = $0 "\n"
        } else {
          doc = doc $0 "\n"
        }
        if (!kind_captured && $1 == "kind:") {
          kind_captured = 1
          if ($2 == "RequireImageDigest" || $2 == "RequireImageSignature") {
            skip_doc = 1
          }
        }
      }
      END {
        flush_doc()
      }
    ' \
  | kubectl apply -f - 2>&1 \
  | awk '$0 !~ /^Warning: tls: failed to find any PEM data in certificate input$/'
