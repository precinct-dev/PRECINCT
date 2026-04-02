#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="${POC_DIR:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
cd "${POC_DIR}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

fail() {
  echo "[FAIL] $1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd kustomize

out="${TMP_DIR}/local-overlay.yaml"
kustomize build infra/eks/overlays/local >"${out}"

python3 - "${out}" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()

for service in ("precinct-gateway", "precinct-control"):
    parts = [part for part in text.split('---') if 'kind: Deployment' in part and f'name: {service}' in part]
    if not parts:
        print(f"[FAIL] local overlay missing {service} deployment", file=sys.stderr)
        sys.exit(1)

    dep = parts[0]

    def must_have(pattern: str, message: str) -> None:
        if not re.search(pattern, dep, re.MULTILINE):
            print(f"[FAIL] {message}", file=sys.stderr)
            sys.exit(1)

    must_have(r'name:\s*SPIFFE_MODE\s+value:\s*"?dev"?', f"local overlay {service} must run in SPIFFE_MODE=dev")
    must_have(r'name:\s*SPIFFE_TRUST_DOMAIN\s+value:\s*"?poc\.local"?', f"local overlay {service} must resolve header-declared demo identities against poc.local")
    must_have(r'name:\s*ALLOW_INSECURE_DEV_MODE\s+value:\s*"?1"?', f"local overlay {service} must explicitly acknowledge dev-mode identity headers")

print("[PASS] local K8s demo identity wiring matches the canonical poc.local dev demo contract")
PY
