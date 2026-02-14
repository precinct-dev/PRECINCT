# NetworkPolicies - EKS Deployment

Story: RFA-9fv.4

## Architecture

NetworkPolicies enforce network segmentation between namespaces in the EKS
deployment. The design follows a default-deny model where all traffic is
blocked unless explicitly permitted.

### Traffic Flow Diagram

```
                 +-------------------------------+
                 | Namespaces with ingress label |
                 | networking.agentic.io/        |
                 | gateway-ingress-allowed=true  |
                 +---------------+---------------+
                                 |
                                 | ALLOW: port 9090
                                 v
               +----------+----------+        +-------------------+
 gateway ns -> |  Security Gateway   | -----> | kube-dns (port 53)|
               |                     | -----> | SPIKE (port 8443) |
               +----------+----------+        +-------------------+
                          |
                          | ALLOW: port 8081
                          |   (gateway -> tools ONLY)
                          v
               +----------+----------+        +-------------------+
 tools ns ---> |   MCP Tool Server   | -----> | kube-dns (port 53)|
               |                     | -----> | Internal CIDRs    |
               +---------------------+   X--> | Public Internet   |
                                               +-------------------+
```

### Policy Summary

| Policy | Namespace | Direction | Rule |
|--------|-----------|-----------|------|
| `default-deny-all` | gateway | Ingress+Egress | Deny all |
| `default-deny-all` | tools | Ingress+Egress | Deny all |
| `gateway-allow-ingress` | gateway | Ingress | Allow labeled namespaces -> port 9090 |
| `gateway-allow-egress` | gateway | Egress | Allow -> tools:8081, spike:8443, dns:53 |
| `mcp-server-allow-ingress` | tools | Ingress | Allow gateway -> port 8081 only |
| `mcp-server-allow-egress` | tools | Egress | Allow -> dns:53, internal CIDRs only |

## Prerequisites

- NetworkPolicy-capable CNI (Calico or Cilium) installed in EKS
- Gateway and tools namespaces must exist before applying policies

## Quick Reference

```bash
# Deploy all policies
make deploy

# Verify policies applied
make verify

# Validate manifests offline
make dry-run

# Remove all policies
make undeploy
```

## Testing NetworkPolicy Enforcement

See story RFA-9fv.8 for comprehensive NetworkPolicy verification tests.

Quick manual verification:

```bash
# Test 1: Tool pod rejects traffic from non-gateway namespace
kubectl run test-pod --image=busybox -n default --restart=Never -- \
  wget -q -O- --timeout=3 http://mcp-server.tools.svc.cluster.local:8081/health
# Expected: timeout/connection refused

# Test 2: Tool pod cannot reach public internet
kubectl exec -n tools <mcp-server-pod> -- \
  python3 -c "import urllib.request; urllib.request.urlopen('https://example.com')"
# Expected: connection error

# Test 3: Gateway CAN reach tool pod
kubectl exec -n gateway <gateway-pod> -- \
  wget -q -O- http://mcp-server.tools.svc.cluster.local:8081/health
# Expected: {"status": "ok"}
```

## Allowlist Strategy

- Gateway ingress boundary: only namespaces explicitly marked with
  `networking.agentic.io/gateway-ingress-allowed: "true"` can reach gateway pods.
- Tool egress boundary: DNS + RFC1918 private ranges only (no default public internet).
- If a tool needs external public egress, add a dedicated reviewed allow rule
  (prefer egress proxy/FQDN policy) rather than widening the baseline policy.
