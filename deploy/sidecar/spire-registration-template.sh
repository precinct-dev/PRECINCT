#!/bin/sh
# ------------------------------------------------------------------------------
# SPIRE Registration Entry Template for Third-Party Tools
# Story: OC-ofhi
#
# Generates SPIRE registration commands for third-party tools that use the
# Envoy sidecar for SPIFFE identity. Supports both Docker Compose and K8s
# deployment modes.
#
# Usage:
#   ./spire-registration-template.sh --tool-name mcp2cli --env dev
#   ./spire-registration-template.sh --tool-name dspy-agent --env dev --mode k8s
#   ./spire-registration-template.sh --tool-name langraph --env dev --mode compose
#
# Options:
#   --tool-name NAME   Tool identifier (e.g., mcp2cli, dspy-agent, langraph)
#   --env ENV          Environment (dev, staging, prod). Default: dev
#   --mode MODE        Deployment mode: compose or k8s. Default: compose
#   --namespace NS     K8s namespace (k8s mode only). Default: agents
#   --sa SA            K8s service account (k8s mode only). Default: <tool-name>
#   --trust-domain TD  SPIFFE trust domain. Default: poc.local
#   --dry-run          Print commands without executing
#   --help             Show this help
#
# SPIFFE ID format (matches config/spiffe-ids.yaml schema):
#   spiffe://<trust-domain>/agents/mcp-client/<tool-name>/<env>
#
# Compose selectors (matches scripts/register-spire-entries.sh pattern):
#   docker:label:spiffe-id:<tool-name>
#
# K8s selectors (matches deploy/terraform/spire/registration-entries.yaml pattern):
#   k8s:ns:<namespace>
#   k8s:sa:<service-account>
# ------------------------------------------------------------------------------

set -eu

# Defaults
TOOL_NAME=""
ENV="dev"
MODE="compose"
NAMESPACE="agents"
SA=""
TRUST_DOMAIN="poc.local"
DRY_RUN=0

usage() {
    sed -n '2,/^# ---/p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --tool-name)   TOOL_NAME="$2"; shift 2 ;;
        --env)         ENV="$2"; shift 2 ;;
        --mode)        MODE="$2"; shift 2 ;;
        --namespace)   NAMESPACE="$2"; shift 2 ;;
        --sa)          SA="$2"; shift 2 ;;
        --trust-domain) TRUST_DOMAIN="$2"; shift 2 ;;
        --dry-run)     DRY_RUN=1; shift ;;
        --help|-h)     usage ;;
        *)             echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TOOL_NAME" ]; then
    echo "Error: --tool-name is required" >&2
    echo "Usage: $0 --tool-name <name> [--env <env>] [--mode compose|k8s]" >&2
    exit 1
fi

# Default service account to tool name
if [ -z "$SA" ]; then
    SA="$TOOL_NAME"
fi

# Validate mode
case "$MODE" in
    compose|k8s) ;;
    *) echo "Error: --mode must be 'compose' or 'k8s'" >&2; exit 1 ;;
esac

# Validate env
case "$ENV" in
    dev|staging|prod) ;;
    *) echo "Error: --env must be 'dev', 'staging', or 'prod'" >&2; exit 1 ;;
esac

SPIFFE_ID="spiffe://${TRUST_DOMAIN}/agents/mcp-client/${TOOL_NAME}/${ENV}"

echo "# SPIRE Registration Entry for: ${TOOL_NAME}"
echo "# SPIFFE ID: ${SPIFFE_ID}"
echo "# Mode: ${MODE}"
echo "# Environment: ${ENV}"
echo ""

if [ "$MODE" = "compose" ]; then
    # Docker Compose mode: use docker:label selectors
    # Matches the pattern in scripts/register-spire-entries.sh
    SOCK="/tmp/spire-server/private/api.sock"

    cat <<ENTRY_EOF
# Docker Compose SPIRE registration command.
# Run inside the spire-server container or via spire-entry-registrar:
#
#   docker exec spire-server sh -c '<command below>'
#
# Or add to scripts/register-spire-entries.sh using the reg() helper:
#
#   reg "spiffe://${TRUST_DOMAIN}/agents/mcp-client/${TOOL_NAME}/${ENV}" \\
#       -selector docker:label:spiffe-id:${TOOL_NAME}

/opt/spire/bin/spire-server entry create \\
    -socketPath ${SOCK} \\
    -parentID \$(cat /tmp/parent-id 2>/dev/null || echo "spiffe://${TRUST_DOMAIN}/spire/agent/join_token/<TOKEN>") \\
    -spiffeID ${SPIFFE_ID} \\
    -selector docker:label:spiffe-id:${TOOL_NAME} \\
    || echo "(entry may already exist)"
ENTRY_EOF

    echo ""
    echo "# Required Docker label on the tool's container:"
    echo "#   labels:"
    echo "#     - \"spiffe-id=${TOOL_NAME}\""

else
    # K8s mode: use k8s:ns + k8s:sa selectors
    # Matches the pattern in deploy/terraform/spire/registration-entries.yaml

    cat <<ENTRY_EOF
# Kubernetes SPIRE registration command.
# Run via kubectl exec into the SPIRE Server pod:
#
#   kubectl -n spire-system exec spire-server-0 -- \\
#     /opt/spire/bin/spire-server entry create \\
#       -socketPath /tmp/spire-server/private/api.sock \\
#       -parentID spiffe://precinct.poc/agent/k8s-psat \\
#       -spiffeID ${SPIFFE_ID} \\
#       -selector k8s:ns:${NAMESPACE} \\
#       -selector k8s:sa:${SA}
#
# Or add to deploy/terraform/spire/registration-entries.yaml register.sh:
#
#   echo "  Workload: ${TOOL_NAME}..."
#   /opt/spire/bin/spire-server entry create \\
#     -socketPath "\$SOCK" \\
#     -parentID spiffe://precinct.poc/agent/k8s-psat \\
#     -spiffeID ${SPIFFE_ID} \\
#     -selector k8s:ns:${NAMESPACE} \\
#     -selector k8s:sa:${SA}

/opt/spire/bin/spire-server entry create \\
    -socketPath /tmp/spire-server/private/api.sock \\
    -parentID spiffe://precinct.poc/agent/k8s-psat \\
    -spiffeID ${SPIFFE_ID} \\
    -selector k8s:ns:${NAMESPACE} \\
    -selector k8s:sa:${SA} \\
    || echo "(entry may already exist)"
ENTRY_EOF

    echo ""
    echo "# Required K8s resources:"
    echo "#   - Namespace: ${NAMESPACE}"
    echo "#   - ServiceAccount: ${SA}"
fi
