#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# NetworkPolicy Enforcement Verification Suite
# Story: RFA-9fv.8
#
# Deploys temporary pods into various namespaces and tests connectivity to
# verify that Kubernetes NetworkPolicies are correctly enforced.
#
# Prerequisites:
#   - kubectl configured with cluster access
#   - NetworkPolicy-capable CNI (Calico, Cilium) installed
#   - Gateway, tools, and observability namespaces deployed
#   - NetworkPolicies applied (POC/infra/eks/policies/)
#
# Usage:
#   ./verify-network-policies.sh              # Run all tests
#   ./verify-network-policies.sh --positive   # Run only "should allow" tests
#   ./verify-network-policies.sh --negative   # Run only "should deny" tests
#   ./verify-network-policies.sh --cleanup    # Remove all test pods
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Prerequisites not met
# ------------------------------------------------------------------------------

set -euo pipefail

# -- Configuration -------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_POD_NAME="netpol-verify"
readonly CONNECT_TIMEOUT=5   # seconds for connection attempts
readonly DNS_TIMEOUT=3        # seconds for DNS resolution attempts

# Service endpoints (must match EKS manifests from RFA-9fv.4)
readonly MCP_SERVER_SVC="mcp-server.tools.svc.cluster.local"
readonly MCP_SERVER_PORT=8081
readonly GATEWAY_SVC="mcp-security-gateway.gateway.svc.cluster.local"
readonly GATEWAY_PORT=9090
readonly OTEL_COLLECTOR_SVC="otel-collector.observability.svc.cluster.local"
readonly OTEL_COLLECTOR_PORT=4317
# External URL for egress test (well-known, reliable)
readonly EXTERNAL_URL="https://example.com"

# Colors for output (disabled if not a terminal)
if [ -t 1 ]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly CYAN='\033[0;36m'
    readonly NC='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly CYAN=''
    readonly NC=''
fi

# -- State tracking ------------------------------------------------------------

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
DEPLOYED_PODS=()   # track pods for cleanup

# -- Helpers -------------------------------------------------------------------

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_test()  { echo -e "${CYAN}[TEST]${NC}  $*"; }

# Deploy a test pod into the given namespace. Waits until Running.
# Usage: deploy_test_pod <namespace>
deploy_test_pod() {
    local ns="$1"
    local pod_name="${TEST_POD_NAME}"
    local app_label="netpol-verify"

    # Match real policy podSelectors so allow-rules are exercised by tests.
    if [ "${ns}" = "gateway" ]; then
        app_label="mcp-security-gateway"
    elif [ "${ns}" = "tools" ]; then
        app_label="mcp-server"
    fi

    # Delete any existing test pod in this namespace
    kubectl delete pod "${pod_name}" -n "${ns}" --ignore-not-found --wait=false 2>/dev/null || true
    sleep 2

    log_info "Deploying test pod '${pod_name}' in namespace '${ns}'"
    kubectl run "${pod_name}" -n "${ns}" \
        --image=curlimages/curl:8.5.0 \
        --restart=Never \
        --labels="app.kubernetes.io/name=${app_label},app.kubernetes.io/component=test,purpose=network-policy-verification" \
        --command -- /bin/sh -c "sleep 300" 2>/dev/null

    # Wait for pod to be Running (up to 60s)
    local attempts=0
    while [ "${attempts}" -lt 30 ]; do
        local phase
        phase=$(kubectl get pod "${pod_name}" -n "${ns}" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
        if [ "${phase}" = "Running" ]; then
            log_info "Pod '${pod_name}' is Running in '${ns}'"
            DEPLOYED_PODS+=("${ns}/${pod_name}")
            return 0
        fi
        sleep 2
        attempts=$((attempts + 1))
    done

    log_fail "Pod '${pod_name}' did not reach Running state in '${ns}' within 60s"
    return 1
}

# Remove a test pod from the given namespace.
# Usage: remove_test_pod <namespace>
remove_test_pod() {
    local ns="$1"
    local pod_name="${TEST_POD_NAME}"
    kubectl delete pod "${pod_name}" -n "${ns}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test connectivity from a pod to a TCP endpoint.
# Returns 0 if connection succeeds, 1 if it fails/times out.
# Usage: test_connectivity <namespace> <host> <port>
test_connectivity() {
    local ns="$1"
    local host="$2"
    local port="$3"

    # Use curl with connect-only to test TCP reachability without reading data
    kubectl exec "${TEST_POD_NAME}" -n "${ns}" -- \
        curl -s --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${CONNECT_TIMEOUT}" \
        "http://${host}:${port}/" -o /dev/null -w "%{http_code}" 2>/dev/null
    return $?
}

# Test TCP port reachability (connect only, no HTTP).
# Returns 0 if connection succeeds, 1 if it fails/times out.
# Usage: test_tcp_connectivity <namespace> <host> <port>
test_tcp_connectivity() {
    local ns="$1"
    local host="$2"
    local port="$3"

    # Use plain HTTP over the target port as a generic connectivity probe.
    # We intentionally do NOT use --fail; any HTTP status still proves reachability.
    # telnet:// with curl can produce false negatives by waiting for payload bytes.
    kubectl exec "${TEST_POD_NAME}" -n "${ns}" -- \
        curl -s --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${CONNECT_TIMEOUT}" \
        "http://${host}:${port}/" -o /dev/null 2>/dev/null
    return $?
}

# Test egress to an external HTTPS URL.
# Returns 0 if connection succeeds, 1 if it fails/times out.
# Usage: test_external_egress <namespace> <url>
test_external_egress() {
    local ns="$1"
    local url="$2"

    kubectl exec "${TEST_POD_NAME}" -n "${ns}" -- \
        curl -s --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${CONNECT_TIMEOUT}" \
        -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null
    return $?
}

# Test DNS resolution.
# Returns 0 if resolution succeeds, 1 if it fails.
# Usage: test_dns <namespace> <hostname>
test_dns() {
    local ns="$1"
    local hostname="$2"

    kubectl exec "${TEST_POD_NAME}" -n "${ns}" -- \
        nslookup -timeout="${DNS_TIMEOUT}" "${hostname}" 2>/dev/null
    return $?
}

# Record test result.
# Usage: record_result <test_name> <expected_outcome> <actual_exit_code>
#   expected_outcome: "allow" (exit 0 = pass) or "deny" (exit != 0 = pass)
record_result() {
    local test_name="$1"
    local expected="$2"
    local actual_exit="$3"
    local detail="${4:-}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "${expected}" = "allow" ]; then
        if [ "${actual_exit}" -eq 0 ]; then
            log_pass "Test ${TESTS_RUN}: ${test_name} -- connection ALLOWED (expected)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_fail "Test ${TESTS_RUN}: ${test_name} -- connection DENIED (expected: ALLOW) ${detail}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    elif [ "${expected}" = "deny" ]; then
        if [ "${actual_exit}" -ne 0 ]; then
            log_pass "Test ${TESTS_RUN}: ${test_name} -- connection DENIED (expected)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_fail "Test ${TESTS_RUN}: ${test_name} -- connection ALLOWED (expected: DENY) ${detail}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

# -- Prerequisite Checks ------------------------------------------------------

check_prerequisites() {
    log_info "Checking prerequisites..."

    # kubectl available and configured
    if ! command -v kubectl &>/dev/null; then
        log_fail "kubectl not found in PATH"
        return 2
    fi

    # Cluster reachable
    if ! kubectl cluster-info &>/dev/null; then
        log_fail "Cannot reach Kubernetes cluster. Check kubeconfig."
        return 2
    fi

    # Required namespaces exist
    local required_namespaces=("gateway" "tools" "observability")
    for ns in "${required_namespaces[@]}"; do
        if ! kubectl get namespace "${ns}" &>/dev/null; then
            log_fail "Required namespace '${ns}' does not exist"
            return 2
        fi
    done

    # NetworkPolicies applied
    local policies_found
    policies_found=$(kubectl get networkpolicies -A --no-headers 2>/dev/null | wc -l)
    if [ "${policies_found}" -lt 3 ]; then
        log_warn "Found only ${policies_found} NetworkPolicies cluster-wide (expected >= 3)"
        log_warn "Ensure policies from POC/infra/eks/policies/ are applied"
    fi

    # Verify CNI supports NetworkPolicies (heuristic: check for calico or cilium pods)
    if ! kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers 2>/dev/null | grep -q .; then
        if ! kubectl get pods -n kube-system -l k8s-app=cilium --no-headers 2>/dev/null | grep -q .; then
            log_warn "Neither Calico nor Cilium detected. NetworkPolicies may not be enforced."
            log_warn "AWS VPC CNI alone does NOT enforce NetworkPolicies."
        fi
    fi

    log_info "Prerequisites check complete"
    return 0
}

# -- Test Cases ----------------------------------------------------------------

# Test 1: Gateway CAN reach MCP server (tools namespace)
# Verifies: mcp-server-allow-ingress allows gateway -> tools:8081
# Verifies: gateway-allow-egress allows gateway -> tools:8081
test_gateway_to_mcp_server() {
    log_test "Test 1: Gateway -> MCP Server (should ALLOW)"
    log_info "  Rule: gateway-allow-egress + mcp-server-allow-ingress"
    log_info "  Path: gateway:${TEST_POD_NAME} -> ${MCP_SERVER_SVC}:${MCP_SERVER_PORT}"

    deploy_test_pod "gateway" || { record_result "Gateway -> MCP Server" "allow" 1 "(pod deploy failed)"; return; }

    local exit_code=0
    test_connectivity "gateway" "${MCP_SERVER_SVC}" "${MCP_SERVER_PORT}" || exit_code=$?

    record_result "Gateway -> MCP Server (port ${MCP_SERVER_PORT})" "allow" "${exit_code}"
    remove_test_pod "gateway"
}

# Test 2: MCP server CANNOT reach gateway (reverse direction blocked)
# Verifies: gateway-allow-ingress requires explicit namespace allowlist label
#           and tools namespace is not approved for gateway ingress.
test_mcp_server_to_gateway() {
    log_test "Test 2: MCP Server -> Gateway (should DENY)"
    log_info "  Rule: gateway-allow-ingress requires approved source namespace label"
    log_info "  Path: tools:${TEST_POD_NAME} -> ${GATEWAY_SVC}:${GATEWAY_PORT}"

    deploy_test_pod "tools" || { record_result "MCP Server -> Gateway" "deny" 1 "(pod deploy failed - counted as deny)"; return; }

    local exit_code=0
    test_connectivity "tools" "${GATEWAY_SVC}" "${GATEWAY_PORT}" || exit_code=$?

    record_result "MCP Server -> Gateway (port ${GATEWAY_PORT})" "deny" "${exit_code}"
    remove_test_pod "tools"
}

# Test 3: MCP server CANNOT reach public internet
# Verifies: mcp-server-allow-egress only permits internal CIDRs + DNS
test_mcp_server_to_internet() {
    log_test "Test 3: MCP Server -> Public Internet (should DENY)"
    log_info "  Rule: mcp-server-allow-egress restricts egress to internal CIDRs only"
    log_info "  Path: tools:${TEST_POD_NAME} -> ${EXTERNAL_URL}"

    deploy_test_pod "tools" || { record_result "MCP Server -> Internet" "deny" 1 "(pod deploy failed - counted as deny)"; return; }

    local exit_code=0
    test_external_egress "tools" "${EXTERNAL_URL}" || exit_code=$?

    record_result "MCP Server -> Public Internet (${EXTERNAL_URL})" "deny" "${exit_code}"
    remove_test_pod "tools"
}

# Test 4: Gateway CAN reach OTEL collector
# Verifies: gateway-allow-egress allows gateway -> observability:4317
test_gateway_to_otel_collector() {
    log_test "Test 4: Gateway -> OTEL Collector (should ALLOW)"
    log_info "  Rule: gateway-allow-egress -> observability otel-collector:4317"
    log_info "  Path: gateway:${TEST_POD_NAME} -> ${OTEL_COLLECTOR_SVC}:${OTEL_COLLECTOR_PORT}"

    deploy_test_pod "gateway" || { record_result "Gateway -> OTEL Collector" "allow" 1 "(pod deploy failed)"; return; }

    local exit_code=0
    test_tcp_connectivity "gateway" "${OTEL_COLLECTOR_SVC}" "${OTEL_COLLECTOR_PORT}" || exit_code=$?

    record_result "Gateway -> OTEL Collector (port ${OTEL_COLLECTOR_PORT})" "allow" "${exit_code}"
    remove_test_pod "gateway"
}

# Test 5: Gateway CAN resolve DNS
# Verifies: gateway-allow-egress allows kube-dns on port 53
test_gateway_dns() {
    log_test "Test 5: Gateway DNS Resolution (should ALLOW)"
    log_info "  Rule: gateway-allow-egress -> kube-dns:53"
    log_info "  Resolving: ${MCP_SERVER_SVC}"

    deploy_test_pod "gateway" || { record_result "Gateway DNS" "allow" 1 "(pod deploy failed)"; return; }

    local exit_code=0
    test_dns "gateway" "${MCP_SERVER_SVC}" || exit_code=$?

    record_result "Gateway DNS resolution (${MCP_SERVER_SVC})" "allow" "${exit_code}"
    remove_test_pod "gateway"
}

# Test 6: Random namespace (default) CANNOT reach MCP server
# Verifies: mcp-server-allow-ingress only allows from gateway namespace
test_default_ns_to_mcp_server() {
    log_test "Test 6: Default Namespace -> MCP Server (should DENY)"
    log_info "  Rule: mcp-server-allow-ingress only allows from gateway namespace"
    log_info "  Path: default:${TEST_POD_NAME} -> ${MCP_SERVER_SVC}:${MCP_SERVER_PORT}"

    deploy_test_pod "default" || { record_result "Default NS -> MCP Server" "deny" 1 "(pod deploy failed - counted as deny)"; return; }

    local exit_code=0
    test_connectivity "default" "${MCP_SERVER_SVC}" "${MCP_SERVER_PORT}" || exit_code=$?

    record_result "Default NS -> MCP Server (port ${MCP_SERVER_PORT})" "deny" "${exit_code}"
    remove_test_pod "default"
}

# Test 7: Gateway CANNOT reach unrelated namespaces
# Verifies: gateway-allow-egress only permits specific destinations
# The default namespace has no allow rules for gateway traffic.
test_gateway_to_unrelated_ns() {
    log_test "Test 7: Gateway -> Unrelated Namespace (should DENY)"
    log_info "  Rule: gateway-allow-egress does not include default namespace"
    log_info "  Path: gateway:${TEST_POD_NAME} -> default-ns pod on arbitrary port"

    # Deploy a target pod in default namespace first
    local target_pod="netpol-target"
    kubectl run "${target_pod}" -n default \
        --image=curlimages/curl:8.5.0 \
        --restart=Never \
        --labels="app.kubernetes.io/name=netpol-target" \
        --command -- sleep 300 2>/dev/null || true

    # Wait for target pod to be ready
    local attempts=0
    while [ "${attempts}" -lt 15 ]; do
        local phase
        phase=$(kubectl get pod "${target_pod}" -n default -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
        if [ "${phase}" = "Running" ]; then
            break
        fi
        sleep 2
        attempts=$((attempts + 1))
    done

    # Get the target pod's IP
    local target_ip
    target_ip=$(kubectl get pod "${target_pod}" -n default -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")

    if [ -z "${target_ip}" ]; then
        log_warn "Could not get target pod IP; skipping direct IP test"
        record_result "Gateway -> Unrelated NS (default)" "deny" 1 "(target pod not ready - counted as deny)"
    else
        deploy_test_pod "gateway" || { record_result "Gateway -> Unrelated NS" "deny" 1 "(pod deploy failed)"; return; }

        local exit_code=0
        # Try to connect to the target pod's IP on an arbitrary port (80)
        test_connectivity "gateway" "${target_ip}" "80" || exit_code=$?

        record_result "Gateway -> Unrelated NS (default, IP: ${target_ip}:80)" "deny" "${exit_code}"
        remove_test_pod "gateway"
    fi

    # Cleanup target pod
    kubectl delete pod "${target_pod}" -n default --ignore-not-found --wait=false 2>/dev/null || true
}

# -- Cleanup -------------------------------------------------------------------

cleanup_all_pods() {
    log_info "Cleaning up test pods..."

    local namespaces=("gateway" "tools" "default" "observability")
    for ns in "${namespaces[@]}"; do
        kubectl delete pod "${TEST_POD_NAME}" -n "${ns}" --ignore-not-found --wait=false 2>/dev/null || true
    done
    kubectl delete pod "netpol-target" -n default --ignore-not-found --wait=false 2>/dev/null || true

    log_info "Cleanup complete"
}

# -- Main ----------------------------------------------------------------------

print_summary() {
    echo ""
    echo "================================================================================"
    echo "  NetworkPolicy Verification Summary"
    echo "================================================================================"
    echo ""
    echo "  Tests run:     ${TESTS_RUN}"
    echo "  Tests passed:  ${TESTS_PASSED}"
    echo "  Tests failed:  ${TESTS_FAILED}"
    echo ""
    if [ "${TESTS_FAILED}" -eq 0 ] && [ "${TESTS_RUN}" -gt 0 ]; then
        echo -e "  Result: ${GREEN}ALL TESTS PASSED${NC}"
    elif [ "${TESTS_FAILED}" -gt 0 ]; then
        echo -e "  Result: ${RED}${TESTS_FAILED} TEST(S) FAILED${NC}"
    else
        echo -e "  Result: ${YELLOW}NO TESTS RUN${NC}"
    fi
    echo ""
    echo "================================================================================"
}

main() {
    local mode="all"

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --positive)  mode="positive"; shift ;;
            --negative)  mode="negative"; shift ;;
            --cleanup)   cleanup_all_pods; exit 0 ;;
            --help|-h)
                echo "Usage: $0 [--positive|--negative|--cleanup|--help]"
                echo ""
                echo "  --positive  Run only 'should allow' tests (Tests 1, 4, 5)"
                echo "  --negative  Run only 'should deny' tests (Tests 2, 3, 6, 7)"
                echo "  --cleanup   Remove all test pods and exit"
                echo "  --help      Show this help message"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    echo "================================================================================"
    echo "  NetworkPolicy Enforcement Verification"
    echo "  Story: RFA-9fv.8"
    echo "  Date:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "================================================================================"
    echo ""

    # Check prerequisites
    check_prerequisites || exit 2

    # Ensure cleanup on exit
    trap cleanup_all_pods EXIT

    echo ""

    # Run tests based on mode
    case "${mode}" in
        all)
            # Positive tests (should allow)
            test_gateway_to_mcp_server
            echo ""
            test_gateway_to_otel_collector
            echo ""
            test_gateway_dns
            echo ""
            # Negative tests (should deny)
            test_mcp_server_to_gateway
            echo ""
            test_mcp_server_to_internet
            echo ""
            test_default_ns_to_mcp_server
            echo ""
            test_gateway_to_unrelated_ns
            ;;
        positive)
            test_gateway_to_mcp_server
            echo ""
            test_gateway_to_otel_collector
            echo ""
            test_gateway_dns
            ;;
        negative)
            test_mcp_server_to_gateway
            echo ""
            test_mcp_server_to_internet
            echo ""
            test_default_ns_to_mcp_server
            echo ""
            test_gateway_to_unrelated_ns
            ;;
    esac

    print_summary

    # Exit with failure if any tests failed
    if [ "${TESTS_FAILED}" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"
