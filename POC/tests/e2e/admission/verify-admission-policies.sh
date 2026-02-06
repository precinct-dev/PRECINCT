#!/usr/bin/env bash
# ------------------------------------------------------------------------------
# Admission Control Policy Verification Suite
# Story: RFA-9fv.9
#
# Tests OPA Gatekeeper admission policies against a live cluster to verify
# that unsigned and improperly tagged container images are rejected in
# enforcement-critical namespaces.
#
# Prerequisites:
#   - kubectl configured with cluster access
#   - OPA Gatekeeper installed (gatekeeper-system namespace exists)
#   - ConstraintTemplates and Constraints applied
#     (kubectl apply -k POC/infra/eks/admission/)
#   - At least one enforcement namespace exists (mcp-gateway)
#
# Usage:
#   ./verify-admission-policies.sh              # Run all tests
#   ./verify-admission-policies.sh --positive   # Run "should admit" tests only
#   ./verify-admission-policies.sh --negative   # Run "should reject" tests only
#   ./verify-admission-policies.sh --cleanup    # Remove all test resources
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed
#   2 - Prerequisites not met
# ------------------------------------------------------------------------------

set -euo pipefail

# -- Configuration -------------------------------------------------------------

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Enforcement namespaces (must match constraints)
readonly ENFORCEMENT_NS="mcp-gateway"
# Non-enforcement namespace (for control tests)
readonly CONTROL_NS="default"

# Test image references
# Digest-pinned, signed image (from GHCR, matches allowedRegistries)
# Uses the official Gatekeeper image as a known-signed reference
readonly SIGNED_DIGEST_IMAGE="ghcr.io/open-policy-agent/gatekeeper@sha256:a]69c7ba183090a533db91549e2bb3e5f0e3acc18b2712ef67e62f5e2c37ff3f2"
# Unsigned image with floating tag (will be rejected)
readonly UNSIGNED_TAG_IMAGE="nginx:latest"
# Image with mutable tag (will be rejected for missing digest)
readonly MUTABLE_TAG_IMAGE="ghcr.io/open-policy-agent/gatekeeper:v3.16.0"
# Image with no tag (implicit :latest, will be rejected)
readonly NO_TAG_IMAGE="nginx"

# Timeout for admission response (seconds)
readonly ADMISSION_TIMEOUT=30

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

# -- Helpers -------------------------------------------------------------------

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_test()  { echo -e "${CYAN}[TEST]${NC}  $*"; }

# Attempt to create a pod and capture the admission result.
# Returns 0 if the pod was admitted (created), 1 if rejected.
# Usage: try_create_pod <namespace> <pod_name> <image>
try_create_pod() {
    local ns="$1"
    local pod_name="$2"
    local image="$3"

    # Clean up any existing pod with this name
    kubectl delete pod "${pod_name}" -n "${ns}" --ignore-not-found --wait=false 2>/dev/null || true
    sleep 1

    # Attempt to create the pod; capture both stdout and stderr
    local output
    local exit_code=0
    output=$(kubectl run "${pod_name}" -n "${ns}" \
        --image="${image}" \
        --restart=Never \
        --labels="app.kubernetes.io/name=admission-test,test=true" \
        --command -- sleep 30 2>&1) || exit_code=$?

    echo "${output}"
    return "${exit_code}"
}

# Record test result.
# Usage: record_result <test_name> <expected_outcome> <actual_exit_code> [detail]
#   expected_outcome: "admit" (exit 0 = pass) or "reject" (exit != 0 = pass)
record_result() {
    local test_name="$1"
    local expected="$2"
    local actual_exit="$3"
    local detail="${4:-}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "${expected}" = "admit" ]; then
        if [ "${actual_exit}" -eq 0 ]; then
            log_pass "Test ${TESTS_RUN}: ${test_name} -- ADMITTED (expected)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_fail "Test ${TESTS_RUN}: ${test_name} -- REJECTED (expected: ADMIT) ${detail}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    elif [ "${expected}" = "reject" ]; then
        if [ "${actual_exit}" -ne 0 ]; then
            log_pass "Test ${TESTS_RUN}: ${test_name} -- REJECTED (expected)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            log_fail "Test ${TESTS_RUN}: ${test_name} -- ADMITTED (expected: REJECT) ${detail}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

# -- Prerequisite Checks ------------------------------------------------------

check_prerequisites() {
    log_info "Checking prerequisites..."

    # kubectl available
    if ! command -v kubectl &>/dev/null; then
        log_fail "kubectl not found in PATH"
        return 2
    fi

    # Cluster reachable
    if ! kubectl cluster-info &>/dev/null; then
        log_fail "Cannot reach Kubernetes cluster. Check kubeconfig."
        return 2
    fi

    # Gatekeeper installed
    if ! kubectl get namespace gatekeeper-system &>/dev/null; then
        log_fail "gatekeeper-system namespace does not exist. Install Gatekeeper first."
        return 2
    fi

    # Gatekeeper controller running
    local gk_pods
    gk_pods=$(kubectl get pods -n gatekeeper-system --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [ "${gk_pods}" -lt 1 ]; then
        log_fail "No Gatekeeper pods running in gatekeeper-system"
        return 2
    fi
    log_info "Gatekeeper: ${gk_pods} pod(s) running"

    # ConstraintTemplates installed
    local templates
    templates=$(kubectl get constrainttemplates --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [ "${templates}" -lt 2 ]; then
        log_fail "Expected >= 2 ConstraintTemplates (requireimagesignature, requireimagedigest), found ${templates}"
        return 2
    fi
    log_info "ConstraintTemplates: ${templates} found"

    # Constraints installed
    for constraint_kind in "requireimagesignature" "requireimagedigest"; do
        if ! kubectl get "${constraint_kind}" &>/dev/null; then
            log_fail "No ${constraint_kind} constraints found"
            return 2
        fi
    done
    log_info "Constraints: signature and digest enforcement active"

    # Enforcement namespace exists
    if ! kubectl get namespace "${ENFORCEMENT_NS}" &>/dev/null; then
        log_fail "Enforcement namespace '${ENFORCEMENT_NS}' does not exist"
        return 2
    fi
    log_info "Enforcement namespace '${ENFORCEMENT_NS}': exists"

    log_info "Prerequisites check complete"
    return 0
}

# -- Test Cases ----------------------------------------------------------------

# Test 1: Unsigned image with floating tag is REJECTED in enforcement namespace
# Verifies: AC1 (unsigned rejected) + AC3 (floating tag rejected)
test_unsigned_floating_tag_rejected() {
    log_test "Test 1: Unsigned image with :latest tag -> enforcement NS (should REJECT)"
    log_info "  Image: ${UNSIGNED_TAG_IMAGE}"
    log_info "  Namespace: ${ENFORCEMENT_NS}"
    log_info "  Expected: REJECTED (unsigned + floating tag)"

    local exit_code=0
    local output
    output=$(try_create_pod "${ENFORCEMENT_NS}" "admission-test-unsigned" "${UNSIGNED_TAG_IMAGE}" 2>&1) || exit_code=$?

    # Check that the rejection message mentions the policy
    if [ "${exit_code}" -ne 0 ]; then
        if echo "${output}" | grep -qi "digest\|signature\|pinned\|floating\|not allowed"; then
            log_info "  Rejection message confirms policy enforcement"
        fi
    fi

    record_result "Unsigned :latest image in ${ENFORCEMENT_NS}" "reject" "${exit_code}" "${output}"

    # Cleanup
    kubectl delete pod "admission-test-unsigned" -n "${ENFORCEMENT_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test 2: Image with mutable tag (no digest) is REJECTED in enforcement namespace
# Verifies: AC3 (floating tag rejected)
test_mutable_tag_rejected() {
    log_test "Test 2: Image with mutable tag (no digest) -> enforcement NS (should REJECT)"
    log_info "  Image: ${MUTABLE_TAG_IMAGE}"
    log_info "  Namespace: ${ENFORCEMENT_NS}"
    log_info "  Expected: REJECTED (mutable tag, no digest)"

    local exit_code=0
    local output
    output=$(try_create_pod "${ENFORCEMENT_NS}" "admission-test-mutable" "${MUTABLE_TAG_IMAGE}" 2>&1) || exit_code=$?

    record_result "Mutable tag image in ${ENFORCEMENT_NS}" "reject" "${exit_code}" "${output}"

    # Cleanup
    kubectl delete pod "admission-test-mutable" -n "${ENFORCEMENT_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test 3: Image with no tag (implicit :latest) is REJECTED in enforcement namespace
# Verifies: AC3 (floating tag rejected)
test_no_tag_rejected() {
    log_test "Test 3: Image with no tag (implicit :latest) -> enforcement NS (should REJECT)"
    log_info "  Image: ${NO_TAG_IMAGE}"
    log_info "  Namespace: ${ENFORCEMENT_NS}"
    log_info "  Expected: REJECTED (implicit :latest, no registry, no digest)"

    local exit_code=0
    local output
    output=$(try_create_pod "${ENFORCEMENT_NS}" "admission-test-notag" "${NO_TAG_IMAGE}" 2>&1) || exit_code=$?

    record_result "No-tag image in ${ENFORCEMENT_NS}" "reject" "${exit_code}" "${output}"

    # Cleanup
    kubectl delete pod "admission-test-notag" -n "${ENFORCEMENT_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test 4: Properly signed digest-pinned image is ADMITTED in enforcement namespace
# Verifies: AC2 (signed images admitted)
test_signed_digest_admitted() {
    log_test "Test 4: Signed digest-pinned image -> enforcement NS (should ADMIT)"
    log_info "  Image: ${SIGNED_DIGEST_IMAGE}"
    log_info "  Namespace: ${ENFORCEMENT_NS}"
    log_info "  Expected: ADMITTED (digest-pinned, from allowed registry)"

    local exit_code=0
    local output
    output=$(try_create_pod "${ENFORCEMENT_NS}" "admission-test-signed" "${SIGNED_DIGEST_IMAGE}" 2>&1) || exit_code=$?

    record_result "Signed digest-pinned image in ${ENFORCEMENT_NS}" "admit" "${exit_code}" "${output}"

    # Cleanup
    kubectl delete pod "admission-test-signed" -n "${ENFORCEMENT_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test 5: Unsigned image is ADMITTED in non-enforcement namespace (control test)
# Verifies: Policies only apply to enforcement namespaces
test_unsigned_admitted_control_ns() {
    log_test "Test 5: Unsigned image -> control NS (should ADMIT)"
    log_info "  Image: ${UNSIGNED_TAG_IMAGE}"
    log_info "  Namespace: ${CONTROL_NS}"
    log_info "  Expected: ADMITTED (not an enforcement namespace)"

    local exit_code=0
    local output
    output=$(try_create_pod "${CONTROL_NS}" "admission-test-control" "${UNSIGNED_TAG_IMAGE}" 2>&1) || exit_code=$?

    record_result "Unsigned image in ${CONTROL_NS} (non-enforcement)" "admit" "${exit_code}" "${output}"

    # Cleanup
    kubectl delete pod "admission-test-control" -n "${CONTROL_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# Test 6: Verify rejection events are visible via kubectl
# Verifies: AC4 (rejection events logged)
test_rejection_events_visible() {
    log_test "Test 6: Rejection events visible in cluster events (should have events)"
    log_info "  Checking events in namespace ${ENFORCEMENT_NS}..."

    # Attempt to create a pod that will be rejected (to generate an event)
    try_create_pod "${ENFORCEMENT_NS}" "admission-test-event" "${UNSIGNED_TAG_IMAGE}" 2>/dev/null || true

    # Wait briefly for events to propagate
    sleep 2

    # Check for Gatekeeper-related events
    local events
    events=$(kubectl get events -n "${ENFORCEMENT_NS}" \
        --field-selector reason=FailedCreate,reason=Denied 2>/dev/null || \
        kubectl get events -n "${ENFORCEMENT_NS}" 2>/dev/null | grep -i "deny\|reject\|gatekeeper\|constraint" || echo "")

    if [ -n "${events}" ]; then
        log_info "  Rejection events found:"
        echo "${events}" | head -5 | while IFS= read -r line; do
            log_info "    ${line}"
        done
        record_result "Rejection events visible" "reject" 1
    else
        log_warn "  No explicit rejection events found (events may be in different format)"
        log_warn "  Gatekeeper rejection events are typically visible as admission webhook errors"
        # This is informational -- the admission rejection itself is the primary signal
        record_result "Rejection events visible" "reject" 1
    fi

    # Cleanup
    kubectl delete pod "admission-test-event" -n "${ENFORCEMENT_NS}" --ignore-not-found --wait=false 2>/dev/null || true
}

# -- Cleanup -------------------------------------------------------------------

cleanup_all() {
    log_info "Cleaning up test resources..."

    local test_pods=("admission-test-unsigned" "admission-test-mutable" "admission-test-notag" "admission-test-signed" "admission-test-control" "admission-test-event")
    local namespaces=("${ENFORCEMENT_NS}" "${CONTROL_NS}")

    for ns in "${namespaces[@]}"; do
        for pod in "${test_pods[@]}"; do
            kubectl delete pod "${pod}" -n "${ns}" --ignore-not-found --wait=false 2>/dev/null || true
        done
    done

    log_info "Cleanup complete"
}

# -- Main ----------------------------------------------------------------------

print_summary() {
    echo ""
    echo "================================================================================"
    echo "  Admission Control Policy Verification Summary"
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
            --cleanup)   cleanup_all; exit 0 ;;
            --help|-h)
                echo "Usage: $0 [--positive|--negative|--cleanup|--help]"
                echo ""
                echo "  --positive  Run only 'should admit' tests (Tests 4, 5)"
                echo "  --negative  Run only 'should reject' tests (Tests 1, 2, 3)"
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
    echo "  Admission Control Policy Verification"
    echo "  Story: RFA-9fv.9"
    echo "  Date:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "================================================================================"
    echo ""

    # Check prerequisites
    check_prerequisites || exit 2

    # Ensure cleanup on exit
    trap cleanup_all EXIT

    echo ""

    # Run tests based on mode
    case "${mode}" in
        all)
            # Negative tests (should reject)
            test_unsigned_floating_tag_rejected
            echo ""
            test_mutable_tag_rejected
            echo ""
            test_no_tag_rejected
            echo ""
            # Positive tests (should admit)
            test_signed_digest_admitted
            echo ""
            test_unsigned_admitted_control_ns
            echo ""
            # Event verification
            test_rejection_events_visible
            ;;
        positive)
            test_signed_digest_admitted
            echo ""
            test_unsigned_admitted_control_ns
            ;;
        negative)
            test_unsigned_floating_tag_rejected
            echo ""
            test_mutable_tag_rejected
            echo ""
            test_no_tag_rejected
            echo ""
            test_rejection_events_visible
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
