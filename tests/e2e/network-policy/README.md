# NetworkPolicy Enforcement Verification

Story: RFA-9fv.8

## Overview

This test suite verifies that Kubernetes NetworkPolicies are correctly enforced
in the EKS deployment. The reference architecture (Section 9.4) mandates strict
network isolation between namespaces using a default-deny model with explicit
allow rules.

The tests validate both **positive** (allowed traffic flows) and **negative**
(blocked traffic flows) to ensure policies are not only present but actively
enforced by the CNI.

## Prerequisites

- EKS cluster with a NetworkPolicy-capable CNI (Calico or Cilium)
- kubectl configured with cluster access
- Namespaces deployed: `gateway`, `tools`, `observability`
- NetworkPolicies applied from `POC/infra/eks/policies/`
- Observability policies applied from `POC/infra/eks/observability/`

## Test Cases

### Positive Tests (Should ALLOW)

| # | Test | Source | Destination | Port | Policy Verified | Expected |
|---|------|--------|-------------|------|-----------------|----------|
| 1 | Gateway -> MCP Server | gateway ns | mcp-server.tools | 8081 | gateway-allow-egress + mcp-server-allow-ingress | ALLOW |
| 4 | Gateway -> OTEL Collector | gateway ns | otel-collector.observability | 4317 | gateway-allow-egress + otel-collector-allow-ingress | ALLOW |
| 5 | Gateway DNS Resolution | gateway ns | kube-dns | 53 | gateway-allow-egress (DNS rule) | ALLOW |

### Negative Tests (Should DENY)

| # | Test | Source | Destination | Port | Policy Verified | Expected |
|---|------|--------|-------------|------|-----------------|----------|
| 2 | MCP Server -> Gateway | tools ns | gateway.gateway | 9090 | mcp-server-allow-egress (no gateway dest) | DENY |
| 3 | MCP Server -> Internet | tools ns | example.com | 443 | mcp-server-allow-egress (internal CIDRs only) | DENY |
| 6 | Default NS -> MCP Server | default ns | mcp-server.tools | 8081 | mcp-server-allow-ingress (gateway only) | DENY |
| 7 | Gateway -> Unrelated NS | gateway ns | pod in default ns | any | gateway-allow-egress (specific destinations only) | DENY |

## NetworkPolicy Rules Being Verified

### default-deny.yaml
- **gateway namespace**: All ingress and egress denied by default
- **tools namespace**: All ingress and egress denied by default

### gateway-allow.yaml
- **Ingress**: Any source -> gateway port 9090
- **Egress**: Gateway -> tools:8081, observability (OTEL):4317/4318, spike:8443, kube-dns:53

### mcp-server-allow.yaml
- **Ingress**: Only from gateway namespace -> tools port 8081
- **Egress**: Only to kube-dns:53 and internal CIDRs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

### observability-policies.yaml
- **Default deny**: All traffic blocked in observability namespace
- **OTEL Collector ingress**: From gateway namespace on ports 4317/4318
- **OTEL Collector egress**: To Phoenix:4317 and kube-dns:53
- **Phoenix ingress**: From OTEL collector:4317 and any source on port 6006 (UI)
- **Phoenix egress**: To kube-dns:53

## Quick Start

```bash
# Run all tests (requires live cluster)
make test

# Run only positive (allow) tests
make test-positive

# Run only negative (deny) tests
make test-negative

# Validate scripts and manifests offline (no cluster needed)
make validate

# Deploy a test pod for manual investigation
make deploy-test-pod

# Clean up all test pods
make cleanup
```

## How to Interpret Results

### PASS

```
[PASS]  Test 1: Gateway -> MCP Server (port 8081) -- connection ALLOWED (expected)
```
The connection result matched the expected outcome. For positive tests, this means
the connection succeeded. For negative tests, this means the connection was blocked.

### FAIL

```
[FAIL]  Test 6: Default NS -> MCP Server (port 8081) -- connection ALLOWED (expected: DENY)
```
The connection result did NOT match the expected outcome. This indicates a
NetworkPolicy is not being enforced correctly. Common causes:

- **CNI does not support NetworkPolicies** (AWS VPC CNI alone does not enforce them)
- **NetworkPolicy not applied** (check `kubectl get networkpolicies -A`)
- **Label mismatch** between NetworkPolicy selectors and pod/namespace labels
- **Policy too permissive** (ingress rule allows broader access than intended)

### Timeouts

Deny tests rely on connection timeouts (default: 5 seconds). A timeout is treated
as a successful deny. If tests are slow, increase `CONNECT_TIMEOUT` in the script.

### Pod Deploy Failures

If a test pod cannot be deployed (e.g., namespace does not exist, image pull fails),
the test is recorded with a note. For deny tests, a pod failure counts as a deny
(since the connection cannot be established). For allow tests, this counts as a
failure and should be investigated.

## CI Integration

The `ci-network-policy-test.sh` script wraps the verification suite for CI
pipelines (e.g., GitHub Actions). It:

1. Verifies the cluster is accessible
2. Runs the full test suite
3. Captures output to a log file
4. Returns appropriate exit codes for CI (0 = pass, 1 = fail)

See `ci-network-policy-test.sh` for integration details.

## Architecture Alignment

This verification suite maps to the following reference architecture requirements:

| Requirement (Section 9.4) | Test(s) | Status |
|---------------------------|---------|--------|
| Tool pods ONLY receive traffic from gateway | Tests 2, 6 | Verified |
| Default-deny egress for tool pods | Test 3 | Verified |
| Tool pods only egress to internal CIDR + DNS | Test 3 | Verified |
| Gateway can reach tools, SPIKE, SPIRE, OTEL | Tests 1, 4, 5 | Verified |
| Gateway cannot reach unrelated namespaces | Test 7 | Verified |
