# Deployment Patterns: Docker Compose vs Kubernetes

This document classifies all security controls in the PRECINCT
by their deployment mode: **Universal** (present in both Docker Compose and Kubernetes),
**K8s-Native** (Kubernetes only), or **K8s-Equivalent** (different mechanism, same outcome).

The purpose is twofold:

1. Prevent evaluators from concluding the architecture has gaps when controls are
   intentionally K8s-only (the Docker Compose stack is a development/evaluation
   environment, not a production deployment).
2. Provide honest documentation of the architecture's boundaries, as required by
   the design principle of honest limitations.

This classification is referenced by the compliance report for controls marked
"Documented Only" (see `tools/compliance/control_taxonomy.yaml`).

---

## 1. Universal Controls (Docker Compose AND Kubernetes)

These controls are enforced by the PRECINCT Gateway's 13-middleware chain.
They execute identically in both deployment modes because the gateway binary is the
same -- only the orchestration layer differs.

| Step | Middleware | Taxonomy Area | Function | Control IDs |
|------|-----------|---------------|----------|-------------|
| 1 | `RequestSizeLimit` | size_limit | Limits inbound request body size to prevent resource exhaustion | GW-AVAIL-003 |
| 2 | `BodyCapture` | (infrastructure) | Captures request body into context for downstream middleware inspection | -- |
| 3 | `SPIFFEAuth` | spiffe_auth | Validates SPIFFE SVIDs presented over mTLS; extracts agent identity | GW-AUTH-001, GW-AUTH-002, GW-AUTH-003, GW-TRANS-001, GW-TRANS-002 |
| 4 | `AuditLog` | audit | Writes structured JSON audit entries with tamper-evident SHA-256 hash chain | GW-AUDIT-001, GW-AUDIT-002, GW-AUDIT-003, GW-AUDIT-004 |
| 5 | `ToolRegistryVerify` | tool_registry | Verifies tool name exists in registry and checks SHA-256 description hash | GW-SC-003 |
| 6 | `OPAPolicy` | opa | Evaluates OPA Rego policies for authorization (SPIFFE grants, path-based ACL, destinations) | GW-AUTHZ-001, GW-AUTHZ-002, GW-AUTHZ-003, GW-AUTHZ-004 |
| 7 | `DLPMiddleware` | dlp | Scans request bodies for PII patterns (SSN, credit card, email) | GW-DLP-001, GW-DLP-003, GW-DLP-004, GW-DLP-005 |
| 8 | `SessionContextMiddleware` | session_context | Tracks per-agent session state, computes risk scores for anomaly detection | GW-SESS-001, GW-SESS-002, GW-SESS-003 |
| 9 | `StepUpGating` | step_up_gating | Risk scoring + destination allowlist check + guard model for high-risk tools | GW-SCAN-002 |
| 10 | `DeepScanMiddleware` | deep_scan | Async deep content scanning for malicious payloads and tool poisoning | GW-SCAN-001, GW-SCAN-003 |
| 11 | `RateLimitMiddleware` | rate_limiter | Per-agent token bucket rate limiting (distributed via KeyDB when available) | GW-AVAIL-001 |
| 12 | `CircuitBreakerMiddleware` | circuit_breaker | Protects upstream MCP servers from cascading failures | GW-AVAIL-002 |
| 13 | `TokenSubstitution` | spike_token, spike_redeemer | Late-binding secret substitution via SPIKE Nexus; agents never see real secrets | GW-SEC-001, GW-SEC-002, GW-SEC-003 |
| 14 | `ResponseFirewall` | response_firewall | Intercepts upstream responses; DLP on responses, data handle-ization | GW-DLP-002 |

**Note on step numbering**: Steps 1-13 are the middleware chain applied to every request.
Step 14 (ResponseFirewall) wraps the reverse proxy and intercepts responses before they
flow back through the chain. Token substitution (step 13) is intentionally the innermost
middleware -- no other middleware sees real secrets.

`NewToolRegistryScopeResolver` is also part of tool registry enforcement path and must be
kept aligned with `ToolRegistryVerify` behavior when policy scopes evolve.

All 13 middleware controls plus the response firewall are identical in Docker Compose
and Kubernetes deployments because they are compiled into the same Go binary
(`mcp-security-gateway`).

---

## 2. K8s-Native Controls (Kubernetes Only)

These controls rely on Kubernetes primitives that have no equivalent in Docker Compose.
Each entry documents what it does, why it is absent from Docker Compose, what evaluators
should know, and the production recommendation.

### 2.1 NetworkPolicies

**What it does**: Default-deny ingress and egress policies in the `gateway` and `tools`
namespaces. Only explicitly allowed traffic (gateway-to-MCP-server, MCP-server-to-S3)
can flow. All other network paths are blocked at the CNI level.

**Manifests**: `infra/eks/policies/default-deny.yaml`, `infra/eks/policies/gateway-allow.yaml`,
`infra/eks/policies/mcp-server-allow.yaml`

**Why not in Docker Compose**: Docker bridge networking does not support NetworkPolicy
enforcement. All containers on the same Docker network can reach each other. There is no
CNI plugin (Calico, Cilium) equivalent in Docker Compose.

**Evaluator guidance**: The Docker Compose stack does not have network segmentation. This
is an accepted limitation of the development environment. The gateway enforces
authorization at the application layer (OPA policy, step 6) regardless of network
topology, so unauthorized tool invocations are still blocked. However, network-level
isolation is a defense-in-depth measure that is only available in Kubernetes.

**Production recommendation**: Deploy with a NetworkPolicy-capable CNI (Calico or Cilium).
Apply default-deny in all namespaces. Use the provided manifests as a baseline and extend
per-namespace allow rules for your topology.

### 2.2 PodSecurityAdmission (Pod Security Standards)

**What it does**: Enforces the `restricted` Pod Security Standard on the `gateway` and
`tools` namespaces. This prevents privilege escalation, requires non-root containers,
enforces read-only root filesystems, and drops all Linux capabilities. Applied via
namespace labels (`pod-security.kubernetes.io/enforce: restricted`).

**Manifests**: `infra/eks/gateway/gateway-namespace.yaml` (labels on namespace metadata)

**Why not in Docker Compose**: Docker Compose has no built-in admission controller that
enforces Pod Security Standards. While individual `docker-compose.yml` directives
(`security_opt`, `read_only`, `user`) can approximate some restrictions, there is no
cluster-wide enforcement mechanism, and Docker does not reject containers that violate
the policy -- it simply runs them.

**Evaluator guidance**: The Docker Compose environment runs containers with default
Docker security settings. The gateway container itself is built to run as non-root
(defined in the Dockerfile), but the enforcement mechanism is absent. In Kubernetes,
the kubelet rejects pods that violate the restricted profile at admission time.

**Production recommendation**: Apply `restricted` Pod Security Standards to all
namespaces containing workloads. Use `baseline` for system namespaces where
`restricted` is impractical. Never use `privileged`.

### 2.3 Cosign Admission (sigstore/policy-controller)

**What it does**: The sigstore policy-controller webhook intercepts pod admission
requests and verifies that container images have valid cosign signatures. Signatures
are verified against the Fulcio CA (keyless OIDC via GitHub Actions) and the Rekor
transparency log. Unsigned or tampered images are rejected at admission time.

**Manifests**: `infra/eks/admission/policy-controller/cluster-image-policy.yaml`,
`infra/eks/admission/policy-controller/deployment.yaml`,
`infra/eks/admission/policy-controller/webhook.yaml`

**Why not in Docker Compose**: Docker Compose builds images from source (`docker compose
build`). The supply chain is the source code itself, not a remote registry. There is
no admission webhook mechanism in Docker to intercept `docker run` and verify signatures
before starting a container. The images exist only locally and are not pulled from a
registry where signature verification would be meaningful.

**Evaluator guidance**: Supply chain integrity in Docker Compose is achieved through
source code review and build reproducibility (the Dockerfiles are in the repository).
In Kubernetes, images are pulled from registries (GHCR) where signature verification
at admission time adds a trust boundary. These are complementary models, not a gap.

**Production recommendation**: Deploy sigstore/policy-controller. Sign all CI-produced
images with `cosign sign --yes` (keyless mode). Configure `ClusterImagePolicy` resources
to require signatures for all application namespaces. Exempt system images
(registry.k8s.io, AWS ECR) via a separate policy.

### 2.4 OPA Gatekeeper Admission

**What it does**: OPA Gatekeeper intercepts Kubernetes admission requests and evaluates
them against ConstraintTemplates. In this architecture, Gatekeeper enforces supply chain
policies: image digest pinning (no `:latest` tags) and registry allowlisting (only
approved registries). This is distinct from the gateway's OPA engine (step 6), which
enforces tool-level authorization.

**Manifests**: `infra/eks/admission/gatekeeper-system.yaml`,
`infra/eks/admission/constraint-templates/require-image-digest.yaml`,
`infra/eks/admission/constraint-templates/require-image-signature.yaml`,
`infra/eks/admission/constraints/enforce-image-digest.yaml`,
`infra/eks/admission/constraints/enforce-image-signature.yaml`

**Why not in Docker Compose**: Same rationale as cosign admission -- Docker Compose has
no admission webhook mechanism. Additionally, the Gatekeeper policies (digest pinning,
registry allowlists) apply to container orchestration decisions that do not exist in
Docker Compose, where images are built locally.

**Evaluator guidance**: Do not conflate the gateway's OPA policy engine (middleware step
6, which authorizes MCP tool invocations) with Gatekeeper (which enforces Kubernetes
admission policies). Both use OPA/Rego, but they operate at different layers: gateway OPA
is an application-level control (Universal), while Gatekeeper is an infrastructure-level
control (K8s-Native).

**Production recommendation**: Deploy OPA Gatekeeper alongside the policy-controller.
Define ConstraintTemplates for: image digest pinning, registry allowlisting, label
requirements, and resource limits. Run in `dryrun` mode initially to identify violations
before switching to `deny`.

### 2.5 Encrypted Persistent Volumes (Encrypted PVCs)

**What it does**: In EKS, persistent volumes (used by SPIRE Server for its datastore
and KeyDB for session persistence) are backed by encrypted EBS volumes. AWS KMS
encryption at rest protects SPIRE registration entries, trust bundles, and session data.

**Manifests**: Configured via the EKS Terraform module (`infra/eks/main.tf`) and
StorageClass annotations, not individual YAML manifests.

**Why not in Docker Compose**: Docker Compose volumes are ephemeral by design in the development
environment. The SPIRE datastore and KeyDB data are stored in Docker volumes on the host
filesystem. Host-level disk encryption (FileVault on macOS, LUKS on Linux) may provide
equivalent protection, but it is outside the scope of Docker Compose configuration.

**Evaluator guidance**: Data at rest encryption in the development stack depends on the host operating
system's disk encryption settings, which are outside the architecture's control. In
Kubernetes, the architecture explicitly provisions encrypted PVCs via AWS KMS, giving
the operator auditable control over encryption keys.

**Production recommendation**: Use encrypted StorageClasses with AWS KMS customer-managed
keys (CMKs). Enable envelope encryption for Kubernetes secrets
(`EncryptionConfiguration`). Rotate KMS keys on a schedule aligned with your compliance
framework.

### 2.6 SPIRE Node Attestation (k8s_psat)

**What it does**: In EKS/managed Kubernetes, SPIRE agents attest to the server using
Kubernetes Projected Service Account Tokens (`k8s_psat`). The SPIRE server validates
these tokens against the cluster's OIDC provider, establishing cryptographic proof that
the agent is running in a specific Kubernetes cluster. This provides strong node identity
tied to the Kubernetes control plane.

**Manifests**: `infra/eks/spire/agent-configmap.yaml` (k8s_psat configuration)

**Why not in Docker Compose**: Docker Desktop's kubeadm-provisioned clusters lack an OIDC
provider, so `k8s_psat` attestation does not work. The Docker Compose deployment uses
`join_token` attestation instead, where the SPIRE server issues a one-time token that the
agent uses to bootstrap trust. This is an intentional design choice documented in the
RFA-7bh retrospective, not a security gap.

**Evaluator guidance**: `join_token` attestation is appropriate for development and
evaluation environments. It establishes the same trust relationship (agent proves identity
to server), but via a shared secret rather than Kubernetes-native identity federation.
The SVID certificates issued to workloads are identical in both modes -- only the node
attestation mechanism differs.

**Production recommendation**: Use `k8s_psat` attestation in managed Kubernetes clusters
(EKS, GKE, AKS) that have OIDC providers configured. Reserve `join_token` for Docker
Desktop local development. For bare-metal Kubernetes, evaluate `k8s_sat` or
`x509pop` attestation based on your cluster's identity capabilities.

---

## 3. K8s-Equivalent Controls (Different Mechanism, Same Outcome)

These controls achieve the same security outcome in both deployment modes, but use
different underlying mechanisms.

### 3.1 Mutual TLS (SPIFFE SVIDs)

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| **SVID issuance** | SPIRE Server issues X.509 SVIDs | SPIRE Server issues X.509 SVIDs |
| **Node attestation** | `join_token` (one-time bootstrap) | `k8s_psat` (OIDC-backed, see 2.6) |
| **Workload attestation** | `docker` attestor (container labels) | `k8s` attestor (namespace, service account, pod labels) |
| **Trust domain** | `poc.local` | `agentic-ref-arch.poc` |
| **SVID rotation** | Automatic via go-spiffe v2 X509Source | Automatic via go-spiffe v2 X509Source |
| **Outcome** | mTLS between gateway, MCP servers, KeyDB | mTLS between gateway, MCP servers, KeyDB |

The mTLS implementation is identical at the application layer. The `go-spiffe` v2 SDK's
`X509Source` handles SVID rotation in both environments. The only differences are in the
attestation path (how workload identity is established) and the trust domain name.

### 3.2 Session Persistence (KeyDB)

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| **Backend** | KeyDB container on Docker bridge network | KeyDB Deployment in `data` namespace |
| **Connection** | `redis://keydb:6379` (plain) or `rediss://keydb:6380` (mTLS) | `rediss://keydb.data.svc:6380` (mTLS) |
| **Session TTL** | Configurable (default: 1 hour) | Configurable (default: 1 hour) |
| **Data at rest** | Docker volume (host-encrypted if host supports it) | Encrypted PVC via AWS KMS |
| **GDPR deletion** | `make gdpr-delete SPIFFE_ID=...` | Same command, targets K8s KeyDB |
| **Outcome** | Distributed session persistence with GDPR right-to-deletion | Same |

Session data format, TTL behavior, and GDPR deletion logic are identical. The
difference is in transport encryption (optional mTLS in Docker Compose, mandatory mTLS
in Kubernetes) and storage encryption (host-dependent vs AWS KMS-managed).

### 3.3 Rate Limiting (KeyDB)

| Aspect | Docker Compose | Kubernetes |
|--------|---------------|------------|
| **Backend** | KeyDB container (shared with session store) | KeyDB Deployment (shared with session store) |
| **Algorithm** | Token bucket per SPIFFE ID | Token bucket per SPIFFE ID |
| **Connection** | Same Redis client as session store | Same Redis client as session store |
| **Outcome** | Distributed rate limiting across gateway instances | Same |

The rate limiting implementation uses the same `KeyDBRateLimitStore` in both environments.
The Redis client shares the connection pool with the session store.

---

## Limitations and Honest Assessment

### What Docker Compose Does NOT Provide

1. **Network segmentation**: All containers share a bridge network. There is no
   network-level isolation between the gateway and MCP servers.
2. **Admission control**: No mechanism to reject containers based on image signatures,
   digests, or security policies at deployment time.
3. **Pod security enforcement**: No runtime enforcement of security profiles (non-root,
   read-only filesystem, capability drops) at the orchestration layer.
4. **Encrypted storage (by architecture)**: Storage encryption depends on the host OS,
   not on the architecture's configuration.
5. **Strong node identity**: `join_token` attestation is a shared-secret model, not
   an OIDC-backed cryptographic identity like `k8s_psat`.

### Why These Limitations Are Acceptable

The Docker Compose deployment is a **development and evaluation environment**. Its
purpose is to:

- Allow evaluators to run the full security control chain locally in under 30 minutes
- Demonstrate that the 13-middleware chain works identically regardless of orchestration
- Provide a realistic development environment for iterating on controls

The K8s-only controls are defense-in-depth measures that strengthen the security
posture in production. Their absence in Docker Compose does not diminish the application-
layer controls, which are the primary security boundary.

### Evaluator Summary

| Category | Docker Compose | Kubernetes | Delta |
|----------|---------------|------------|-------|
| Application-layer controls (13 middleware) | All 13 | All 13 | None |
| Response firewall | Yes | Yes | None |
| mTLS (SPIFFE) | Yes (join_token) | Yes (k8s_psat) | Attestation path only |
| Session persistence | Yes (KeyDB) | Yes (KeyDB) | Storage encryption |
| Rate limiting | Yes (KeyDB) | Yes (KeyDB) | None |
| Network segmentation | No | Yes (NetworkPolicies) | K8s-only |
| Admission control | No | Yes (Gatekeeper + cosign) | K8s-only |
| Pod security enforcement | No | Yes (PSA restricted) | K8s-only |
| Encrypted persistent storage | Host-dependent | Yes (AWS KMS) | K8s-managed |
| OIDC-backed node identity | No | Yes (k8s_psat) | K8s-only |

---

## References

- Gateway middleware chain: `internal/gateway/gateway.go` (Handler method)
- Control taxonomy: `tools/compliance/control_taxonomy.yaml`
- K8s NetworkPolicies: `infra/eks/policies/`
- K8s admission control: `infra/eks/admission/`
- SPIRE configuration (Docker): `config/spire/agent.conf`
- SPIRE configuration (K8s base): `infra/eks/spire/agent-configmap.yaml`
- SPIRE configuration (K8s local): `infra/eks/overlays/local/patch-spire-agent-config.yaml`
- RFA-7bh retrospective: Docker Desktop uses join_token (not k8s_psat) -- intentional
