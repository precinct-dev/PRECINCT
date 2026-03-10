# PRECINCT: A Reference Architecture for Governing Autonomous Agents

> How we took an insecure AI assistant framework and made it enterprise-ready --
> without changing a single line of its source code.

---

## The Problem

By 2026, Gartner projects that 30% of enterprises will rely on AI agents that act independently -- triggering transactions, accessing data, invoking external services, and completing tasks with minimal human oversight. This autonomy introduces security challenges that traditional Identity and Access Management frameworks were never designed to handle.

Traditional IAM was built for deterministic applications and static service accounts. AI agents are none of those things. They reason about goals, adapt their behavior dynamically, and access resources in ways no static policy can predict. The result is an authorization crisis: the security primitives we've relied on for decades don't map to how agents actually work.

Every organization deploying AI agents faces three choices:

1. **Build from scratch** -- absorb years of security and governance drag while agents ship unprotected.
2. **Buy a closed platform** -- accept vendor lock-in, opaque controls, and reduced auditability.
3. **Adopt an open, production-oriented reference architecture** -- keep control, portability, and full auditability.

This document describes option 3.

---

## What This Architecture Does

PRECINCT is a **centralized enforcement gateway** that sits between AI agents and the resources they access. It implements a 13-layer defense-in-depth middleware chain that governs five critical planes:

- **Model plane** -- LLM provider egress (which models agents can call, with what data)
- **Tool plane** -- tool execution authorization (MCP and non-MCP protocols)
- **Context plane** -- governed memory and session-level risk tracking
- **Control loop plane** -- execution pattern boundaries
- **Ingress plane** -- webhook, queue, and event normalization

The key principle: **centralized control, decentralized innovation**. Teams choose their own frameworks, providers, and orchestration patterns. They cannot bypass boundary controls for model egress, tool execution, or data handling.

### The Middleware Chain

Every request passes through these layers, in order:

| Step | Layer | Function |
|------|-------|----------|
| 0 | Request Metrics | OTel counters for operational visibility |
| 1 | Request Size Limit | Reject payloads exceeding 10 MB |
| 2 | Body Capture | Cache request body for downstream inspection |
| 3 | SPIFFE Auth | Cryptographic workload identity verification |
| 4 | Audit Log | Hash-chained JSONL with decision correlation IDs |
| 5 | Tool Registry Verify | SHA-256 hash validation, rug-pull detection |
| 6 | OPA Policy | Rego-based fine-grained authorization |
| 7 | DLP Scanning | Credential blocking, PII flagging, injection detection |
| 8 | Session Context | Cross-request risk tracking and exfiltration detection |
| 9 | Step-Up Gating | Risk scoring with guard model dispatch for high-risk actions |
| 10 | Deep Scan | Async prompt injection detection via guard model |
| 11 | Rate Limiting | Per-identity token bucket (distributed via KeyDB) |
| 12 | Circuit Breaker | Upstream cascade protection |
| 13 | Token Substitution | Late-binding secret injection via SPIKE Nexus |

Token substitution happens last, immediately before the upstream proxy. This is deliberate: no middleware layer ever sees raw credentials. Even if an earlier layer is compromised, secrets remain opaque references until the final egress point.

### Core Technology Stack

Five open components work together:

| Component | Role |
|-----------|------|
| **SPIFFE/SPIRE** | Cryptographic workload identity. Every agent, service, and gateway gets a short-lived X.509 SVID that rotates continuously. No static API keys or service account passwords. |
| **SPIKE** | SPIFFE-native secrets management with Shamir Secret Sharing. Agents receive opaque tokens; the gateway substitutes real credentials at egress time. Even if the LLM is compromised, it never sees actual secrets. |
| **OPA** | Policy-as-code authorization. Fine-grained rules match SPIFFE identity patterns to tool allowlists, path restrictions, destination constraints, and step-up requirements. |
| **PRECINCT Gateway** | The enforcement point. 38,000 lines of Go implementing the 13-layer chain, with 62,000 lines of tests. Structured logging (slog), OTel metrics, and hash-chained audit events. |
| **Phoenix + OpenSearch Dashboards (optional)** | Dual observability backends: Phoenix for request-trace waterfalls; OpenSearch Dashboards for indexed audit/compliance investigations and evidence export workflows. |

---

## Case Study: Porting OpenClaw

To demonstrate that this architecture works for real applications -- not just synthetic demos -- we ported [OpenClaw](https://github.com/nicholasgasior/openclaw), a feature-rich AI assistant framework, through the gateway. OpenClaw is a TypeScript/Node.js application that connects to 13+ messaging channels (WhatsApp, Telegram, Slack, Discord, Signal, iMessage, and more) and orchestrates AI agents across them.

OpenClaw is a good test case precisely because it was not designed with enterprise security in mind. It's a local-first personal assistant. It has direct access to shell commands, file systems, browser automation, and arbitrary tool execution. In a corporate environment, deploying it without governance would be a non-starter.

### What We Did Not Do

We did not fork OpenClaw. We did not patch it. We did not add security middleware inside its codebase. We did not modify a single line of its source code.

### What We Did

We wrote a thin **adapter layer** that translates OpenClaw's communication protocols to the gateway's internal models:

**HTTP Adapter** (`openclaw_http_adapter.go`) -- translates two OpenClaw endpoints:
- `/v1/responses` -- model inference requests routed through policy mediation
- `/tools/invoke` -- tool execution requests evaluated for admission (not executed -- the gateway returns a policy decision, not a tool result)

**WebSocket Adapter** (`openclaw_ws_adapter.go`) -- translates the OpenClaw control plane:
- `/openclaw/ws` -- persistent WebSocket connection for device management, health checks, and event streaming
- Role-based access control: "operator" role gets broad access; "node" role requires device identity and explicit scope grants

**Contract Layer** (`internal/integrations/openclaw/http_adapter.go`) -- defines the translation contract:
- Request parsing and validation
- Policy target resolution (maps OpenClaw tools to gateway capability IDs)
- Dangerous tool blocking at admission (shell, exec, session management commands blocked at the HTTP boundary)

The total adapter code is approximately 800 lines of Go. The gateway core, middleware chain, and policy engine required zero modifications.

### What the Gateway Enforces

When OpenClaw sends a request through the adapter, it passes through the full 13-layer middleware chain. Here's what happens to a typical tool invocation:

```
OpenClaw sends: POST /tools/invoke { "tool": "bash", "args": { "command": "ls -la" } }

Step 3  - SPIFFE Auth: Verify OpenClaw's workload identity (SVID)
Step 4  - Audit: Log the request with decision ID, trace ID, SPIFFE ID
Step 5  - Tool Registry: Verify bash tool hash matches registered hash
Step 6  - OPA Policy: Check if this SPIFFE ID is authorized for bash
Step 7  - DLP Scan: Check args for credentials, PII, injection patterns
Step 8  - Session Context: Update session risk score (bash = critical tool)
Step 9  - Step-Up Gating: Risk score > 6 -- require step-up approval
Step 10 - Deep Scan: Run guard model on input for prompt injection
Step 11 - Rate Limit: Check per-identity rate budget
Step 12 - Circuit Breaker: Verify upstream is healthy

Result: DENIED at Step 9 (step-up required for critical tools)
Response: { "code": "stepup_required", "middleware_step": 9, ... }
```

The same OpenClaw instance, connecting to the same gateway, can invoke `tavily_search` (medium risk, no step-up required) without friction while being blocked from `bash` (critical risk, step-up mandatory). The policy is external to OpenClaw -- it doesn't know or care about these rules.

### The Only Code Change Required

After 50+ upstream commits to OpenClaw, we found exactly one contract drift: the WebSocket protocol now requires node-role connections to present a device identity during the `connect` handshake. This required a 12-line guard in the WS adapter:

```go
if role == "node" {
    device, hasDevice := frame.Params["device"].(map[string]any)
    nodeDeviceID := ""
    if hasDevice {
        nodeDeviceID = strings.TrimSpace(getStringAttr(device, "id", ""))
    }
    if nodeDeviceID == "" {
        g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden,
            reasonWSDeviceRequired, "node role requires device identity",
            decisionID, traceID)
        return nil
    }
}
```

That's it. Twelve lines in the adapter. Zero lines in OpenClaw. Zero lines in the gateway core.

---

## Deploying It

The architecture runs in two modes: Docker Compose for local development and Kubernetes for production.

### Docker Compose

Start the full stack:

```bash
cd POC
make up
```

This brings up:

| Service | Role |
|---------|------|
| `spire-server` + `spire-agent` | Workload identity attestation |
| `spike-nexus` + `spike-keeper-1` | Secret vault with Shamir key splitting |
| `spike-bootstrap` + `spike-secret-seeder` | One-shot initialization and secret provisioning |
| `keydb` | Distributed session store and rate-limit state |
| `mock-mcp-server` | Upstream tool server (MCP Streamable HTTP) |
| `mock-guard-model` | Prompt injection detection model |
| `mcp-security-gateway` | The 13-layer enforcement gateway |

Run the full E2E demo (28 test scenarios):

```bash
make demo-compose
```

This exercises:
- MCP Streamable HTTP transport through all 13 middleware layers
- Fail-closed validation (malformed requests rejected, not silently passed)
- SPIFFE authentication (missing identity = HTTP 401)
- Tool registry verification (unknown tools denied, hash mismatches denied)
- DLP credential blocking (AWS keys, GitHub tokens, PEM keys, passwords)
- DLP injection detection (6 prompt injection patterns flagged)
- SPIKE token substitution (opaque ref="deadbeef" redeemed for real secret)
- Rate limiting (burst exceeding budget triggers HTTP 429)
- Exfiltration detection (sensitive read followed by external send)
- Model egress through policy mediation

Tear down:

```bash
make down
```

### Kubernetes

The same architecture deploys to any conformant Kubernetes cluster -- EKS, GKE, AKS, kind, k3s, Docker Desktop.

Deploy:

```bash
make k8s-up
```

This uses Kustomize overlays to deploy across isolated namespaces:

| Namespace | Components |
|-----------|------------|
| `spire-system` | SPIRE Server (StatefulSet), SPIRE Agent (DaemonSet), Token Generator (Job) |
| `spike-system` | SPIKE Nexus, Keeper, Bootstrap, Secret Seeder |
| `gateway` | PRECINCT Gateway |
| `tools` | MCP Server |
| `data` | KeyDB |
| `observability` | OTel Collector, Phoenix UI, optional OpenSearch + Dashboards + audit forwarder |
| `gatekeeper-system` | OPA Gatekeeper for admission control |
| `cosign-system` | Sigstore Policy Controller for image verification |

Every namespace has default-deny NetworkPolicies. Ingress and egress are explicitly allowlisted per service. The gateway pod runs as non-root (UID 65532), with a read-only root filesystem, all capabilities dropped, and a RuntimeDefault seccomp profile.

Run the E2E demo against the k8s deployment:

```bash
make demo-k8s
```

Tear down:

```bash
make k8s-down
```

---

## Verifying It's Secure

Security claims without evidence are marketing. Here's how to verify each control.

### 1. Identity: SPIFFE/SPIRE

Verify that every service has a valid, rotated SVID:

```bash
# Docker Compose
docker compose exec spire-agent /opt/spire/bin/spire-agent api fetch x509 \
  -socketPath /tmp/spire-agent/public/api.sock

# Kubernetes
kubectl -n spire-system exec -it statefulset/spire-server -- \
  /opt/spire/bin/spire-server entry list
```

Verify that requests without SPIFFE identity are denied:

```bash
curl -s http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq .code
# Returns: "spiffe_auth_required"
```

### 2. Authorization: OPA Policy

Verify that unauthorized SPIFFE IDs are denied:

```bash
curl -s http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/unauthorized/attacker" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"bash"},"id":1}' \
  | jq .code
# Returns: "authz_policy_denied"
```

### 3. Tool Integrity: Registry Verification

Verify that tools with mismatched hashes are stripped from discovery:

```bash
# The demo exercises this as test case 8 (rug-pull protection)
make demo-compose
# Look for: "PROOF: PASS -- rug-pull protection active: tools/list stripped + tools/call denied"
```

### 4. DLP: Credential Blocking

Send a request containing an AWS access key:

```bash
curl -s -X POST http://localhost:9090/ \
  -H "Content-Type: application/json" \
  -H "X-SPIFFE-ID: spiffe://poc.local/agents/mcp-client/dspy-researcher/dev" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"tavily_search","arguments":{"query":"AKIAIOSFODNN7EXAMPLE"}},"id":1}' \
  | jq .code
# Returns: "dlp_credentials_detected"
```

### 5. Secrets: Late-Binding Token Substitution

Verify that agents never see raw credentials:

```bash
# In the demo output, look for:
# "action":"token_substitution"
# "result":"substituted ref=deadbeef spiffe=spiffe://poc.local/..."
# The agent sends ref=deadbeef; SPIKE resolves it to the real secret at egress time.
```

### 6. Audit: Hash-Chained Events

Every audit event includes a `prev_hash` field linking it to the previous event. Verify chain integrity:

```bash
# Each audit line contains:
# "prev_hash": "5e43f7d47f182a64acc52dadb185855ce525ea21e7a0c6aee65cfad0b8371674"
# SHA-256 of the previous event. Breaking the chain requires rewriting all subsequent events.
```

### 7. Rate Limiting: Per-Identity Budgets

```bash
# The demo sends a burst exceeding the rate limit budget
# Look for: "PROOF: PASS -- rate limit enforced: HTTP 429 after burst"
```

### 8. Full E2E Validation

Run the complete validation suite:

```bash
# Docker Compose mode
make demo-compose                          # 28 test scenarios
make demo-compose-strict-observability     # With strict deep scan enforcement
make opensearch-up && make opensearch-seed # Optional indexed evidence profile

# Kubernetes mode
make demo-k8s                              # 28 test scenarios
make k8s-runtime-campaign                  # Machine-readable validation report
make k8s-opensearch-up                     # Optional K8s OpenSearch extension

# Unit + integration tests
go test -race -count=1 ./...               # 1,200+ tests, zero failures
```

---

## Architecture Decisions

Several design choices are worth calling out:

**Boundary enforcement, not framework replacement.** The gateway enforces security at the perimeter. It does not attempt to modify agent internals, inject middleware into framework runtimes, or require agents to call specific security APIs. This is what makes the OpenClaw port possible: the application doesn't know it's being governed.

**Policy decisions, not tool execution.** The `/tools/invoke` endpoint returns admission decisions -- "yes, this tool call is authorized" or "no, here's why" -- not tool results. The application retains control of execution. This prevents the gateway from becoming a bottleneck and avoids coupling to tool-specific execution semantics.

**Structured deny codes over opaque errors.** Every denial returns a machine-readable code (`authz_policy_denied`, `dlp_credentials_detected`, `stepup_required`, etc.), the middleware step where denial occurred, and a decision ID for audit correlation. Agents can programmatically understand why they were denied and adapt.

**Secrets as references, not values.** Agents work with opaque tokens (`ref=deadbeef`) that the gateway resolves to real credentials only at the final egress point. This is the strongest practical defense against credential exfiltration: the LLM never has access to real secrets, so even a fully compromised model context cannot leak them.

**Cloud-agnostic by default.** The Kubernetes manifests work on any conformant cluster. Cloud-specific integrations (IRSA, Workload Identity, Pod Identity) are added as Kustomize overlays, not baked into the base manifests.

---

## What This Proves

The OpenClaw case study demonstrates a general principle: **you can secure agentic AI applications without modifying them**, provided you enforce controls at the right boundary.

The adapter pattern is the key insight. Each application integration is a thin translation layer (~800 lines) that maps application-specific protocols to the gateway's internal model. The gateway's 13-layer middleware chain, policy engine, and audit system are shared infrastructure -- they don't change per application.

This means:

- New applications can be onboarded by writing an adapter, not by retrofitting security into their codebase.
- Security controls evolve independently of applications. When we added OTel metrics, structured logging, or OPA v1 support, zero application code changed.
- Compliance evidence is centralized. One audit log, one policy engine, one identity system -- regardless of how many applications connect.

The architecture is open, auditable, and portable. It runs on Docker Compose for development and any Kubernetes cluster for production. All code is Go, all policies are Rego, all identities are SPIFFE, and all evidence is under your control.

For regulated profiles, any indexed evidence backend must follow the same trust model as core services: secret-managed credentials, TLS/mTLS transport, and identity-bound authorization.

---

*The full source is available at [github.com/precinct-dev/PRECINCT](https://github.com/precinct-dev/PRECINCT). Website: [precinct.dev](https://precinct.dev). Contributions welcome.*
