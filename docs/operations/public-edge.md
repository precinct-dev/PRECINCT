# Public Edge Deployment Runbook

This runbook covers the deployment and operation of the PRECINCT gateway's public edge -- the externally-facing ingress that exposes a restricted subset of gateway routes to the internet.

## Architecture Overview

```
Internet
    |
    v
[TLS Termination]         <-- cert-manager + Ingress controller
    |
    v
[Ingress Resource]        <-- path-based routing (3 allowed paths)
    |
    v
[Gateway Public Listener] <-- HTTP on port 9090 (within the cluster)
    |
    v
[Middleware Chain]         <-- auth, audit, OPA, DLP, rate limiting, etc.
    |
    v
[Upstream MCP Server]     <-- port 8081 in tools namespace
```

Internal workloads continue using the SPIFFE mTLS listener on port 9443. The public listener is a separate HTTP endpoint that sits behind the ingress controller and only serves the approved routes.

## Publicly Exposed Routes

| Path | Method | Purpose |
|------|--------|---------|
| `/` | POST | MCP JSON-RPC endpoint (full middleware chain applied) |
| `/health` | GET | Health check (no authentication required) |
| `/.well-known/oauth-protected-resource` | GET | OAuth discovery (RFC 9728) |

## Routes NOT Exposed Publicly

The following routes are intentionally excluded from the public ingress. They are only accessible via the internal mTLS listener:

| Path | Reason |
|------|--------|
| `/admin/*` | Internal administration -- must never be publicly accessible |
| `/openai/v1/chat/completions` | Internal model plane -- direct model access bypasses governance |
| `/data/dereference` | Internal data operations |
| `/v1/auth/token-exchange` | Token exchange is an internal operation between trusted services |

If any of these routes appear in a public-facing ingress, treat it as a security incident.

## Prerequisites

1. A Kubernetes cluster with a NetworkPolicy-capable CNI (Calico, Cilium, AWS VPC CNI, etc.)
2. An NGINX ingress controller deployed (or equivalent that respects `networking.k8s.io/v1` Ingress)
3. cert-manager installed for automated TLS certificate provisioning
4. The ingress controller namespace labeled for NetworkPolicy selection:

```bash
kubectl label namespace ingress-nginx \
  networking.agentic.io/ingress-controller=true
```

## Deployment

### 1. Configure the hostname

Edit `deploy/k8s/overlays/public/ingress.yaml` and replace `gateway.example.com` with your actual public hostname in both the `tls.hosts` and `rules.host` fields.

### 2. Configure cert-manager issuer

The Ingress assumes a ClusterIssuer named `letsencrypt-prod`. If your issuer has a different name, update the `cert-manager.io/cluster-issuer` annotation.

### 3. Apply the overlay

```bash
# Dry-run first
kubectl apply --dry-run=client -k deploy/k8s/overlays/public

# Apply
kubectl apply -k deploy/k8s/overlays/public
```

### 4. Verify

```bash
# Check Ingress is created
kubectl get ingress -n gateway

# Check TLS certificate provisioning
kubectl get certificate -n gateway

# Test health endpoint
curl -sk https://gateway.example.com/health

# Test that blocked paths return 404
curl -sk https://gateway.example.com/admin/
# Expected: 404 (not routed through ingress)
```

## Network Policies

The public overlay preserves the base default-deny posture. A single additional NetworkPolicy (`allow-ingress-controller-to-gateway`) opens a narrow path:

- **Source**: Pods in any namespace labeled `networking.agentic.io/ingress-controller=true`
- **Destination**: Gateway pods labeled `precinct.io/public-edge=true`
- **Port**: TCP 9090 only

All other traffic to the gateway namespace remains blocked unless explicitly allowed by the base policies.

## Edge Rate Limiting

Rate limiting at the edge is strongly recommended for production deployments. Without it, a single client can saturate the gateway's middleware chain and affect availability for all tenants.

### Enabling NGINX Ingress Rate Limiting

Uncomment and tune the rate-limiting annotations in `deploy/k8s/overlays/public/ingress.yaml`:

```yaml
nginx.ingress.kubernetes.io/limit-rps: "50"
nginx.ingress.kubernetes.io/limit-connections: "20"
nginx.ingress.kubernetes.io/limit-burst-multiplier: "3"
```

| Annotation | Description | Recommended Starting Value |
|------------|-------------|---------------------------|
| `limit-rps` | Max requests per second per client IP | 50 (adjust based on expected traffic) |
| `limit-connections` | Max concurrent connections per client IP | 20 |
| `limit-burst-multiplier` | Burst multiplier for `limit-rps` | 3 (allows short bursts of 150 rps) |

### Layered Rate Limiting Strategy

The gateway itself also enforces application-level rate limiting (via KeyDB-backed middleware). The recommended strategy is:

1. **Edge (ingress)**: Coarse per-IP rate limiting to prevent resource exhaustion. This stops volumetric abuse before it reaches the gateway.
2. **Application (gateway)**: Fine-grained per-tenant/per-session rate limiting with richer context (identity, session, tool). This enforces business policy.

Both layers are complementary. Do not rely on edge rate limiting alone -- it has no awareness of application identity. Do not rely on application rate limiting alone -- it consumes gateway resources before rejecting requests.

### Alternative: External Rate Limiting

For high-traffic deployments, consider an external rate-limiting solution:

- **AWS WAF** rate-based rules (if behind ALB)
- **Cloudflare Rate Limiting** (if behind Cloudflare)
- **Envoy external rate limit service** (if using Envoy-based ingress)

These provide more granular controls (geolocation, bot detection, adaptive throttling) than annotation-based NGINX limits.

## Monitoring and Alerting

Key signals to monitor on the public edge:

| Signal | Source | Alert Threshold |
|--------|--------|-----------------|
| 4xx rate | Ingress controller metrics | Sustained > 50% of total requests |
| 5xx rate | Ingress controller metrics | Any sustained 5xx |
| TLS certificate expiry | cert-manager | < 14 days remaining |
| Request latency (p99) | Ingress controller metrics | > 2s |
| Rate-limited requests | Ingress controller metrics | Sustained spike (potential attack) |
| Gateway health check failures | Liveness/readiness probes | Any failure |

## Troubleshooting

### Ingress returns 503

The ingress controller cannot reach the gateway service. Check:

1. Gateway pods are running: `kubectl get pods -n gateway`
2. Gateway service endpoints exist: `kubectl get endpoints precinct-gateway -n gateway`
3. NetworkPolicy allows ingress controller traffic: verify the ingress controller namespace has the label `networking.agentic.io/ingress-controller=true`

### TLS certificate not provisioning

1. Check cert-manager logs: `kubectl logs -n cert-manager deploy/cert-manager`
2. Check Certificate resource: `kubectl describe certificate precinct-gateway-tls -n gateway`
3. Verify DNS for the hostname resolves to the ingress controller's external IP

### Requests to / return 404 instead of auth error

The gateway's public listener may not be configured. Check:

1. `PUBLIC_LISTEN_PORT` env var is set on the gateway deployment
2. `PUBLIC_ROUTE_ALLOWLIST` includes `/`
3. The gateway logs show the public listener starting on port 9090

### Rate limiting is too aggressive

If legitimate clients are being rate-limited, increase `limit-rps` and `limit-connections` in the ingress annotations. Monitor the ingress controller's rate-limiting metrics to find the right threshold.
