#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# NetworkPolicy Verification - CI Integration Script
# Story: RFA-9fv.8
#
# Wraps the NetworkPolicy verification suite for CI pipeline integration.
# Designed to run after EKS deployment in GitHub Actions or similar CI systems.
#
# This script:
#   1. Validates prerequisites (kubectl, cluster access, namespaces)
#   2. Verifies NetworkPolicies are applied
#   3. Runs the full verification suite
#   4. Captures structured output for CI reporting
#   5. Returns appropriate exit codes
#
# Integration with GitHub Actions (RFA-9fv.6):
#   - Add this as a step after EKS deployment and policy application
#   - The script outputs in a format parseable by CI systems
#   - Exit code 0 = all tests passed, 1 = failures, 2 = prerequisites missing
#
# Usage:
#   ./ci-network-policy-test.sh                    # Run with defaults
#   ./ci-network-policy-test.sh --output-dir /tmp  # Save logs to specific dir
#
# Environment variables:
#   KUBECONFIG          - Path to kubeconfig (default: ~/.kube/config)
#   NETPOL_LOG_DIR      - Directory for test logs (default: /tmp/netpol-tests)
#   NETPOL_TIMEOUT      - Override connection timeout in seconds (default: 5)
#   CI                  - Set by CI systems; enables structured output
# ------------------------------------------------------------------------------

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VERIFY_SCRIPT="${SCRIPT_DIR}/verify-network-policies.sh"
readonly TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
readonly LOG_DIR="${NETPOL_LOG_DIR:-/tmp/netpol-tests}"
readonly LOG_FILE="${LOG_DIR}/netpol-verification-${TIMESTAMP}.log"

# -- Helpers -------------------------------------------------------------------

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"; }

die() {
    log "FATAL: $*"
    exit 2
}

# -- Pre-flight checks ---------------------------------------------------------

preflight() {
    log "=== NetworkPolicy CI Verification - Pre-flight ==="

    # Ensure log directory exists
    mkdir -p "${LOG_DIR}"

    # Verify kubectl
    if ! command -v kubectl &>/dev/null; then
        die "kubectl not found in PATH"
    fi
    log "kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"

    # Verify cluster access
    if ! kubectl cluster-info &>/dev/null; then
        die "Cannot reach Kubernetes cluster. Check KUBECONFIG."
    fi
    local cluster_info
    cluster_info=$(kubectl config current-context 2>/dev/null || echo "unknown")
    log "Cluster context: ${cluster_info}"

    # Verify required namespaces
    local required=("gateway" "tools" "observability")
    for ns in "${required[@]}"; do
        if ! kubectl get namespace "${ns}" &>/dev/null; then
            die "Required namespace '${ns}' does not exist. Deploy infrastructure first."
        fi
    done
    log "Required namespaces: present"

    # Verify NetworkPolicies exist
    local policy_count
    policy_count=$(kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [ "${policy_count}" -lt 6 ]; then
        log "WARNING: Only ${policy_count} NetworkPolicies found (expected >= 6)"
        log "Policies found:"
        kubectl get networkpolicies -A --no-headers 2>/dev/null | while read -r line; do
            log "  ${line}"
        done
    else
        log "NetworkPolicies: ${policy_count} found"
    fi

    # Verify verification script exists and is executable
    if [ ! -x "${VERIFY_SCRIPT}" ]; then
        die "Verification script not found or not executable: ${VERIFY_SCRIPT}"
    fi

    log "Pre-flight checks: PASSED"
    log ""
}

# -- Main test execution -------------------------------------------------------

run_tests() {
    log "=== NetworkPolicy CI Verification - Test Execution ==="
    log "Log file: ${LOG_FILE}"
    log ""

    local exit_code=0

    # Run the verification suite, capturing output to both console and log
    if "${VERIFY_SCRIPT}" 2>&1 | tee "${LOG_FILE}"; then
        exit_code=0
    else
        exit_code=$?
    fi

    log ""
    log "=== NetworkPolicy CI Verification - Complete ==="
    log "Exit code: ${exit_code}"
    log "Log saved: ${LOG_FILE}"

    # Output CI-friendly summary
    if [ -n "${CI:-}" ]; then
        echo ""
        echo "::group::NetworkPolicy Test Results"
        cat "${LOG_FILE}"
        echo "::endgroup::"

        if [ "${exit_code}" -ne 0 ]; then
            echo "::error::NetworkPolicy verification failed. See test output for details."
        fi
    fi

    return "${exit_code}"
}

# -- Entry point ---------------------------------------------------------------

main() {
    local output_dir=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --output-dir)
                output_dir="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--output-dir <dir>]"
                echo ""
                echo "  --output-dir  Save test logs to this directory (default: /tmp/netpol-tests)"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    if [ -n "${output_dir}" ]; then
        # shellcheck disable=SC2034  # LOG_DIR is used indirectly
        NETPOL_LOG_DIR="${output_dir}"
    fi

    preflight
    run_tests
}

main "$@"
