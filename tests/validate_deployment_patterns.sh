#!/usr/bin/env bash
# validate_deployment_patterns.sh
#
# Validates docs/architecture/deployment-patterns.md against the actual codebase.
# Checks:
#   1. All 13 middleware names match the middleware chain in gateway.go
#   2. K8s-native controls have corresponding manifests in deploy/terraform/
#   3. Document mentions all control areas from the control taxonomy
#
# Usage: bash tests/validate_deployment_patterns.sh
# Exit code: 0 = all checks pass, 1 = one or more checks failed
#
# Story: RFA-lo1.3

set -euo pipefail

# Resolve project root relative to this script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DOC="$PROJECT_ROOT/docs/architecture/deployment-patterns.md"
GATEWAY="$PROJECT_ROOT/internal/gateway/gateway.go"
TAXONOMY="$PROJECT_ROOT/tools/compliance/control_taxonomy.yaml"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    printf "  PASS: %s\n" "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    printf "  FAIL: %s\n" "$1"
}

# ---------------------------------------------------------------------------
# Check 0: Required files exist
# ---------------------------------------------------------------------------
printf "\n=== Check 0: Required files exist ===\n"

if [ -f "$DOC" ]; then
    pass "deployment-patterns.md exists"
else
    fail "deployment-patterns.md not found at $DOC"
    printf "\nCannot continue without the document. Aborting.\n"
    exit 1
fi

if [ -f "$GATEWAY" ]; then
    pass "gateway.go exists"
else
    fail "gateway.go not found at $GATEWAY"
    printf "\nCannot continue without gateway.go. Aborting.\n"
    exit 1
fi

# ---------------------------------------------------------------------------
# Check 1: All 13 middleware names in gateway.go are listed in the document
# ---------------------------------------------------------------------------
printf "\n=== Check 1: Middleware chain cross-reference ===\n"

# Extract middleware function names from the Handler() method in gateway.go.
# We specifically look for lines that apply middleware in the chain:
#   handler = middleware.XXX(...)    -- steps 1-13
#   middleware.ResponseFirewall(...) -- step 14 (wraps proxy)
# This avoids picking up constructors (New...) and utility functions.
MIDDLEWARE_NAMES=$(grep -E '(handler = middleware\.|middleware\.ResponseFirewall)' "$GATEWAY" \
    | grep -oE 'middleware\.[A-Z][a-zA-Z]+' \
    | sed 's/middleware\.//' \
    | sort -u)

# The middleware names we expect to find in the document (based on the Handler
# method). We verify each middleware function name appears in the document text.
for mw in $MIDDLEWARE_NAMES; do
    if grep -q "$mw" "$DOC"; then
        pass "Middleware '$mw' found in document"
    else
        fail "Middleware '$mw' NOT found in document"
    fi
done

# Count how many unique middleware functions are in the chain (should be >= 13).
MW_COUNT=$(echo "$MIDDLEWARE_NAMES" | wc -l | tr -d ' ')
if [ "$MW_COUNT" -ge 13 ]; then
    pass "Middleware chain has $MW_COUNT unique functions (>= 13 expected)"
else
    fail "Middleware chain has only $MW_COUNT unique functions (expected >= 13)"
fi

# ---------------------------------------------------------------------------
# Check 2: K8s-native controls have corresponding manifests in deploy/terraform/
# ---------------------------------------------------------------------------
printf "\n=== Check 2: K8s manifest cross-references ===\n"

# NetworkPolicies
if [ -f "$PROJECT_ROOT/deploy/terraform/policies/default-deny.yaml" ]; then
    pass "NetworkPolicy manifest exists: policies/default-deny.yaml"
else
    fail "NetworkPolicy manifest missing: policies/default-deny.yaml"
fi

if [ -f "$PROJECT_ROOT/deploy/terraform/policies/gateway-allow.yaml" ]; then
    pass "NetworkPolicy manifest exists: policies/gateway-allow.yaml"
else
    fail "NetworkPolicy manifest missing: policies/gateway-allow.yaml"
fi

if [ -f "$PROJECT_ROOT/deploy/terraform/policies/mcp-server-allow.yaml" ]; then
    pass "NetworkPolicy manifest exists: policies/mcp-server-allow.yaml"
else
    fail "NetworkPolicy manifest missing: policies/mcp-server-allow.yaml"
fi

# PodSecurityAdmission (namespace labels)
if [ -f "$PROJECT_ROOT/deploy/terraform/gateway/gateway-namespace.yaml" ]; then
    if grep -q "pod-security.kubernetes.io/enforce" "$PROJECT_ROOT/deploy/terraform/gateway/gateway-namespace.yaml"; then
        pass "PodSecurityAdmission labels found in gateway-namespace.yaml"
    else
        fail "PodSecurityAdmission labels NOT found in gateway-namespace.yaml"
    fi
else
    fail "Gateway namespace manifest missing: gateway/gateway-namespace.yaml"
fi

# Cosign admission (policy-controller)
if [ -f "$PROJECT_ROOT/deploy/terraform/admission/policy-controller/cluster-image-policy.yaml" ]; then
    pass "Cosign admission manifest exists: admission/policy-controller/cluster-image-policy.yaml"
else
    fail "Cosign admission manifest missing: admission/policy-controller/cluster-image-policy.yaml"
fi

if [ -f "$PROJECT_ROOT/deploy/terraform/admission/policy-controller/webhook.yaml" ]; then
    pass "Cosign webhook manifest exists: admission/policy-controller/webhook.yaml"
else
    fail "Cosign webhook manifest missing: admission/policy-controller/webhook.yaml"
fi

# OPA Gatekeeper admission
if [ -f "$PROJECT_ROOT/deploy/terraform/admission/gatekeeper-system.yaml" ]; then
    pass "Gatekeeper system manifest exists: admission/gatekeeper-system.yaml"
else
    fail "Gatekeeper system manifest missing: admission/gatekeeper-system.yaml"
fi

if [ -d "$PROJECT_ROOT/deploy/terraform/admission/constraint-templates" ]; then
    CT_COUNT=$(ls "$PROJECT_ROOT/deploy/terraform/admission/constraint-templates/"*.yaml 2>/dev/null | wc -l | tr -d ' ')
    if [ "$CT_COUNT" -gt 0 ]; then
        pass "Gatekeeper ConstraintTemplates found: $CT_COUNT templates"
    else
        fail "Gatekeeper ConstraintTemplates directory exists but is empty"
    fi
else
    fail "Gatekeeper constraint-templates directory missing"
fi

if [ -d "$PROJECT_ROOT/deploy/terraform/admission/constraints" ]; then
    C_COUNT=$(ls "$PROJECT_ROOT/deploy/terraform/admission/constraints/"*.yaml 2>/dev/null | wc -l | tr -d ' ')
    if [ "$C_COUNT" -gt 0 ]; then
        pass "Gatekeeper Constraints found: $C_COUNT constraints"
    else
        fail "Gatekeeper Constraints directory exists but is empty"
    fi
else
    fail "Gatekeeper constraints directory missing"
fi

# SPIRE agent configs (k8s_psat for EKS, join_token for local)
if [ -f "$PROJECT_ROOT/deploy/terraform/spire/agent-configmap.yaml" ]; then
    if grep -q "k8s_psat" "$PROJECT_ROOT/deploy/terraform/spire/agent-configmap.yaml"; then
        pass "SPIRE agent config uses k8s_psat for EKS"
    else
        fail "SPIRE agent config does NOT use k8s_psat for EKS"
    fi
else
    fail "SPIRE agent ConfigMap missing: spire/agent-configmap.yaml"
fi

if [ -f "$PROJECT_ROOT/deploy/terraform/overlays/local/patch-spire-agent-config.yaml" ]; then
    if grep -q "join_token" "$PROJECT_ROOT/deploy/terraform/overlays/local/patch-spire-agent-config.yaml"; then
        pass "Local overlay SPIRE agent uses join_token"
    else
        fail "Local overlay SPIRE agent does NOT use join_token"
    fi
else
    fail "Local overlay SPIRE agent patch missing"
fi

# ---------------------------------------------------------------------------
# Check 3: Document mentions all control areas from the taxonomy
# ---------------------------------------------------------------------------
printf "\n=== Check 3: Control area coverage ===\n"

# Extract unique middleware identifiers from the taxonomy.
# These represent the control areas the document should mention.
if [ -f "$TAXONOMY" ]; then
    # Extract 'middleware: <name>' values from the taxonomy, excluding null
    TAXONOMY_MIDDLEWARES=$(grep -E '^\s+middleware:' "$TAXONOMY" \
        | sed 's/.*middleware:\s*//' \
        | tr -d '"' \
        | grep -v 'null' \
        | sort -u)

    for area in $TAXONOMY_MIDDLEWARES; do
        # The document may use different casing or formatting. Search
        # case-insensitively and also check for the PascalCase form.
        if grep -qi "$area" "$DOC"; then
            pass "Control area '$area' mentioned in document"
        else
            fail "Control area '$area' NOT mentioned in document"
        fi
    done

    # Verify document mentions key frameworks
    for framework in "SOC 2" "ISO 27001" "GDPR" "CCPA"; do
        # These frameworks should at least be referenced via the taxonomy
        # reference or evaluator table. Search case-insensitively.
        if grep -qi "$framework\|control_taxonomy" "$DOC"; then
            pass "Framework reference '$framework' or taxonomy link present"
        else
            fail "No reference to '$framework' or control taxonomy in document"
        fi
    done
else
    printf "  SKIP: control_taxonomy.yaml not found at %s\n" "$TAXONOMY"
    printf "        Cross-reference check skipped.\n"
fi

# ---------------------------------------------------------------------------
# Check 4: Document structure validation
# ---------------------------------------------------------------------------
printf "\n=== Check 4: Document structure ===\n"

# Verify three main sections exist
if grep -q "## 1\. Universal Controls" "$DOC"; then
    pass "Section 1 (Universal Controls) exists"
else
    fail "Section 1 (Universal Controls) missing"
fi

if grep -q "## 2\. K8s-Native Controls" "$DOC"; then
    pass "Section 2 (K8s-Native Controls) exists"
else
    fail "Section 2 (K8s-Native Controls) missing"
fi

if grep -q "## 3\. K8s-Equivalent Controls" "$DOC"; then
    pass "Section 3 (K8s-Equivalent Controls) exists"
else
    fail "Section 3 (K8s-Equivalent Controls) missing"
fi

# Verify K8s-only controls have all four required fields
K8S_CONTROLS=("NetworkPolicies" "PodSecurityAdmission" "Cosign Admission" "OPA Gatekeeper" "Encrypted Persistent Volumes" "SPIRE Node Attestation")

for control in "${K8S_CONTROLS[@]}"; do
    if grep -qi "$control" "$DOC"; then
        pass "K8s-native control '$control' documented"
    else
        fail "K8s-native control '$control' NOT documented"
    fi
done

# Verify each K8s-only subsection has the four required fields
for field in "What it does" "Why not in Docker Compose" "Evaluator guidance" "Production recommendation"; do
    count=$(grep -c "$field" "$DOC" 2>/dev/null || echo "0")
    if [ "$count" -ge 6 ]; then
        pass "Field '$field' appears $count times (>= 6 K8s-only controls)"
    else
        fail "Field '$field' appears only $count times (expected >= 6)"
    fi
done

# Verify K8s-equivalent controls documented
for equiv in "Mutual TLS" "Session Persistence" "Rate Limiting"; do
    if grep -q "$equiv" "$DOC"; then
        pass "K8s-equivalent control '$equiv' documented"
    else
        fail "K8s-equivalent control '$equiv' NOT documented"
    fi
done

# Verify honest limitations section
if grep -q "Limitations" "$DOC"; then
    pass "Limitations section exists"
else
    fail "Limitations section missing (DESIGN.md principle: honest limitations)"
fi

# Verify join_token attestation is mentioned (retro learning)
if grep -q "join_token" "$DOC"; then
    pass "join_token attestation documented (RFA-7bh retro learning)"
else
    fail "join_token attestation NOT documented (required by retro learning)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== Summary ===\n"
printf "  Total checks: %d\n" "$TOTAL_COUNT"
printf "  Passed:       %d\n" "$PASS_COUNT"
printf "  Failed:       %d\n" "$FAIL_COUNT"

if [ "$FAIL_COUNT" -gt 0 ]; then
    printf "\nVALIDATION FAILED: %d check(s) did not pass.\n" "$FAIL_COUNT"
    exit 1
else
    printf "\nVALIDATION PASSED: All checks passed.\n"
    exit 0
fi
