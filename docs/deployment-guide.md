# Deployment Guide

This is the consolidated deployment guide for the PRECINCT. It covers Docker Compose (development/evaluation), local Kubernetes (Docker Desktop), and references to EKS production deployment.

For detailed architecture context, see [Deployment Patterns](architecture/deployment-patterns.md).
For Kubernetes-first hardening decisions, see [Kubernetes-First Hardening Guide](architecture/k8s-hardening-portability-matrix.md).
For K8s runtime validation checklist and campaign execution, see [K8s Runtime Validation Campaign](architecture/k8s-runtime-validation-campaign.md).
For portability class decisions per feature, see [Compose Backport Decision Ledger](architecture/compose-backport-decision-ledger.md).
For non-K8s adaptation constraints, see [Non-K8s Cloud Adaptation Guide](architecture/non-k8s-cloud-adaptation-guide.md).
For strategy and tradeoffs when onboarding apps without upstream source modifications, see [No-Upstream-Modification Integration Playbook](sdk/no-upstream-mod-integration-playbook.md).
For framework taxonomy mappings (MITRE ATLAS + OWASP Agentic Top 10) on audit signal keys, see [Framework Taxonomy Signal Mappings](security/framework-taxonomy-signal-mappings.md).
For OpenSearch-based compliance/forensics observability, see [OpenSearch Observability Profile](operations/opensearch-observability.md).
For detailed prerequisites, see [Prerequisites](getting-started/prerequisites.md).
For EKS IaC details, see [EKS IaC Approach](eks-iac.md).

---

## 1. Prerequisites

### Required Tools

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Docker | 25.0+ | Container runtime |
| Docker Compose | 2.24+ | Multi-container orchestration |
| Go | 1.26.1 | Building gateway and services |
| make | Any | Build automation |
| Bash | 4.0+ | Setup and demo scripts |

### For Local Kubernetes Deployment

All of the above, plus:

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| kubectl | 1.28+ | Kubernetes CLI |
| kustomize | 5.0+ | Kubernetes manifest templating |
| Docker Desktop | Latest | Local Kubernetes cluster (enable in Settings > Kubernetes) |

**Minimum hardware for K8s:** 4 CPU cores, 8GB RAM allocated to Docker Desktop.

### For Compliance Reporting

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.11+ | Compliance report generation |
| uv | Any | Python package management |

### Optional Tools

| Tool | Purpose | Impact if Missing |
|------|---------|-------------------|
| opa | OPA Rego policy unit tests | OPA policy tests skipped |
| golangci-lint | Go linting | Falls back to `go fmt` + `go vet` |
| cosign | Container image signature verification | Image signing disabled |
| gosec | Go source code security scanning | Go security scan skipped |
| trivy | Container image and filesystem CVE scanning | Vulnerability scan skipped |
| syft | SBOM generation | Supply chain transparency reduced |

---

## 2. Docker Compose Deployment (Step-by-Step)

This is the primary deployment mode for development and evaluation. The full 13-layer security middleware chain runs identically in Docker Compose and Kubernetes.

### Step 1: Start Phoenix Observability Stack

```bash
make phoenix-up
```

This creates the `phoenix-observability-network`, starts the Phoenix trace viewer and the OpenTelemetry collector, and waits for health checks.
`make up` will auto-start Phoenix if the shared observability network is missing,
but explicit `make phoenix-up` remains the recommended preflight when you want
observability online before core services.

**Verify:** Open [http://localhost:6006](http://localhost:6006) in a browser. The Phoenix UI should load.

### Step 2: Start All Services

```bash
make up
```

This command:
1. Creates `.env` from `.env.example` if it does not exist (set `GROQ_API_KEY` in `.env` for deep scan)
2. Ensures `phoenix-observability-network` exists (auto-starts Phoenix when missing)
3. Builds all container images from source
4. Starts all services with dependency ordering
5. Waits for all health checks to pass (`--wait --wait-timeout 180`)
6. Registers SPIRE workload entries via `make register-spire`

The full startup sequence takes 1-3 minutes depending on hardware. The `--wait` flag ensures the command does not return until every service reports healthy.

### Step 3: Verify

```bash
# Check all services are healthy
docker compose ps

# Run the full E2E demo test suite (21 Go + 22 Python = 43 tests)
make demo-compose
```

All services should show status `healthy`. The demo suite exercises all 13 middleware layers with real requests through the gateway.

Latest external-app latest-source validation evidence (2026-02-16 UTC):

- `bash tests/e2e/run_all.sh` -> `105 pass / 0 fail / 3 skip` (`tests/e2e/artifacts/rfa-t1hb-run-all-20260216T185105Z.log`)
- Targeted case-study campaign rerun -> `4 pass / 0 fail` (latest campaign artifact in `tests/e2e/artifacts/`)
- `make readiness-state-validate` -> PASS (`tests/e2e/artifacts/rfa-t1hb-readiness-state-20260216T185105Z.log`)
- Final decision package: latest external-app final decision artifact (**GO**, follow-up bug `RFA-655e` accepted/closed)
- Separation model: upstream case-study source remains isolated from this repository; security mediation remains in the gateway and control-plane components.

### Step 4: View Traces

Open [http://localhost:6006](http://localhost:6006). All tool calls produce OpenTelemetry spans visible in the Phoenix trace viewer. Each request shows the full middleware chain execution with timing for every layer.

### Step 5: Cleanup

```bash
# Stop all gateway services (Phoenix keeps running, traces preserved)
make down

# Stop Phoenix stack (preserves trace data for later analysis)
make phoenix-down

# Full cleanup: stop everything, remove volumes and build artifacts
make clean
```

---

## 3. Service Architecture

The Docker Compose stack runs 11 services plus 3 one-shot init containers. Services start in dependency order enforced by health checks and `service_completed_successfully` conditions.

### Identity Infrastructure

| Service | Role | Notes |
|---------|------|-------|
| `spire-server` | SPIFFE identity provider | Issues X.509 SVIDs to all workloads. Trust domain: `poc.local` |
| `spire-agent` | SVID attestor | Runs with `pid: host` for Docker workload attestation. Uses `use_new_container_locator = true` for cgroupv2 |
| `spire-entry-registrar` | One-shot init | Registers SPIFFE IDs for all workloads. Must complete before SPIKE or gateway start |

### Secret Management (SPIKE)

| Service | Role | Notes |
|---------|------|-------|
| `spike-nexus` | Secret store | Late-binding token redemption via SPIFFE mTLS. AES-256-GCM encrypted SQLite backend. Port 8443 |
| `spike-keeper-1` | Key shard holder | Holds the demo/local shard and participates in the release `2-of-3` keeper set |
| `spike-keeper-2` + `spike-keeper-3` | Additional release keepers | Enabled by `docker-compose.prod-intent.yml` and `deploy/terraform/spike/` for multi-share keeper recovery |
| `spike-bootstrap` | One-shot init | Generates root key, splits via Shamir, sends shards to Keeper(s) |
| `spike-secret-seeder` | One-shot init | Seeds demo secrets (`ref=deadbeef`) and creates gateway-read ACL policy via SPIKE Pilot CLI |

### Data and Application

| Service | Role | Notes |
|---------|------|-------|
| `keydb` | Redis-compatible store | Session persistence and distributed rate limiting. Ports 6379 (plain) and 6380 (mTLS) |
| `keydb-svid-init` | One-shot init (prod profile) | Fetches SPIRE SVID and writes PEM files for KeyDB mTLS on port 6380. Only runs in `prod` profile |
| `mock-mcp-server` | Simulated MCP tool server | Speaks MCP Streamable HTTP. Returns canned results for `tavily_search` and `echo` tools. Port 8082 |
| `precinct-gateway` | 13-layer security gateway | The core security enforcement point. Port 9090 (HTTP) and 9443 (mTLS) |

### Service Startup Order

The startup sequence is enforced by Docker Compose `depends_on` conditions:

```
spire-server (healthy)
  -> spire-agent (healthy)
    -> spire-entry-registrar (completed)
        -> spike-keeper-1 (healthy)
          -> spike-nexus (healthy)
            -> spike-bootstrap (completed)
              -> spike-secret-seeder (completed)
                -> precinct-gateway
keydb (healthy) -> precinct-gateway
mock-mcp-server (healthy) -> precinct-gateway
```

The gateway is the last service to start because it requires all identity, secret,
session, and upstream services to be operational. The startup chain above shows
the local/demo single-keeper path; the production-intent compose overlay expands
the keeper stage to `spike-keeper-1`, `spike-keeper-2`, and `spike-keeper-3`.

---

## 4. Kubernetes Local Deployment

This deploys the full stack to Docker Desktop's built-in Kubernetes cluster using Kustomize overlays that adapt EKS manifests for a single-node kubeadm environment.

### ConfigMap Population (Important)

The gateway pod requires a populated `gateway-config` ConfigMap before it can
start. The base manifest ships with a placeholder only. If you deploy without
populating the ConfigMap, the gateway pod will stay in `ContainerCreating` or
`CrashLoopBackOff`.

See [`deploy/k8s/README.md` -- ConfigMap Population](../deploy/k8s/README.md#configmap-population)
for the full list of required keys and population commands. The short version:

```bash
# Populate from canonical config/ directory
make k8s-sync-config
```

`make k8s-up` runs this automatically, but if you apply base manifests manually
(`kubectl apply -k deploy/k8s/base`), you must populate the ConfigMap yourself.

### Step-by-Step

```bash
# 1. Verify Kubernetes prerequisites (installs OPA Gatekeeper, sigstore CRDs)
make k8s-prereqs

# 2. Start local container registry (registry:2 on port 5050)
make k8s-registry

# 3. Deploy full stack to K8s (builds, pushes, applies overlays, waits for rollouts)
make k8s-up

# 3b. Optional: include OpenSearch extension (mTLS + dashboards + audit forwarder)
make k8s-opensearch-up

# 4. Verify
kubectl get pods -A | grep -E '(gateway|spire|spike|data|tools)'

# 5. Run E2E demo against K8s
make demo-k8s

# 6. Run explicit K8s runtime control-plane allow/deny campaign
make k8s-runtime-campaign

# 7. Teardown
make k8s-down
```

### What `make k8s-up` Does

1. **Syncs K8s gateway config** from the canonical `config/` source to `deploy/terraform/overlays/local/gateway-config/` (prevents drift between Compose and K8s)
2. Starts a local registry (`registry:2` on port 5050) and connects it to the `kind` network
3. Builds gateway, mock-mcp-server, spire-agent-wrapper, spike-keeper, and content-scanner images
4. Tags and pushes all images to `localhost:5050`
5. Installs OPA Gatekeeper and sigstore policy-controller CRDs
6. Applies the Kustomize local overlay (`deploy/terraform/overlays/local/`) in two passes:
   - Pass 1: Namespaces, CRDs, services (ConstraintTemplates only)
   - Pass 2: Constraints, policies (after Gatekeeper processes ConstraintTemplates)
7. Generates TLS certs for the policy-controller webhook
8. Waits for all rollouts: SPIRE server/agent, SPIKE keeper/nexus/bootstrap/seeder, KeyDB, MCP server, gateway
9. Registers SPIRE workload entries via `make k8s-register-spire`

### Config Sync Between Compose and K8s

The K8s overlay requires local copies of config files (Kustomize `configMapGenerator` only supports relative paths). These copies are synced automatically by `make k8s-up` from the canonical source in `config/`.

To manually sync or check for drift:

```bash
make k8s-sync-config    # Copy canonical config/ files to K8s overlay
make k8s-check-config   # Check for drift without modifying (CI use)
```

The only K8s-specific file is `extensions-demo-k8s.yaml` (uses cluster DNS instead of Docker Compose hostnames).

To include OpenSearch in local K8s, apply the extension overlay:

- `deploy/terraform/overlays/local-opensearch/` (inherits `overlays/local` and adds `observability/opensearch`)
- `make k8s-opensearch-up` applies this overlay and waits for OpenSearch rollouts

### Local Overlay Adaptations

The local Kustomize overlay (`deploy/terraform/overlays/local/kustomization.yaml`) applies these changes to the EKS base manifests:

| EKS Feature | Local Adaptation |
|-------------|-----------------|
| ALB Ingress | NodePort Service (port 30090) |
| IRSA (IAM Roles for Service Accounts) | Hardcoded K8s Secrets (dev only) |
| EBS CSI StorageClass | Default hostpath StorageClass |
| Route53 DNS | localhost / *.local |
| 3-AZ topology | Single node (1 replica) |
| SPIRE `k8s_psat` node attestor | `join_token` attestor |
| `restricted` Pod Security Standards | `privileged` (required for hostPath volumes) |
| sigstore policy-controller (enforcing) | Scaled to 0 replicas, failurePolicy: Ignore |
| Gatekeeper constraints (deny) | enforcementAction: dryrun |

### Key Notes from Implementation

- **SPIRE 1.10.0 images are distroless** (no `/bin/sh`). The local overlay uses a wrapper image with a shell to read the join token. SPIRE binaries are at `/opt/spire/bin/spire-server`.
- **Docker Desktop kubeadm needs PSS relaxed to `privileged`** for any namespace with hostPath volumes (SPIRE agent socket, SPIRE data directories).
- **SPIRE parent ID detection**: Use `agent list` (not `entry show`) to find the agent's SPIFFE ID for parent ID in entry registration.
- **Docker Desktop K8s does not expose NodePorts to host** via the standard NodePort mechanism in all configurations. Use `kubectl port-forward` if NodePort 30090 is not accessible.
- **Gateway endpoint in K8s**: `http://localhost:30090` (NodePort) or via port-forward.

---

## 5. EKS Production Deployment

For production deployment on AWS EKS, see [EKS IaC Approach](eks-iac.md).

The production deployment uses OpenTofu (Terraform-compatible) with the `terraform-aws-modules/eks` community module. The IaC covers:

- **VPC**: Subnets, security groups, NAT gateways
- **EKS cluster**: Managed node groups, OIDC provider
- **SPIRE**: `k8s_psat` node attestation (OIDC-backed, replacing `join_token`)
- **Gateway**: ALB Ingress, IRSA for AWS service access
- **Admission control**: OPA Gatekeeper (enforce mode), sigstore policy-controller (enforce mode)
- **Storage**: Encrypted PVCs via AWS KMS
- **Network**: NetworkPolicies for default-deny + explicit allow rules

The production deployment enforces the `restricted` Pod Security Standard, real cosign signature verification, and encrypted persistent volumes -- controls that are relaxed or absent in the local development overlay.

---

## 6. Phoenix Observability Setup

Phoenix is a standalone observability stack that persists traces across demo stack teardowns. It runs in a separate Docker Compose file (`docker-compose.phoenix.yml`) with its own Docker network (`phoenix-observability-network`).

### Commands

```bash
# Start Phoenix + OTel collector (creates network, waits for health checks)
make phoenix-up

# Stop Phoenix stack (preserves trace data for later analysis)
make phoenix-down

# Stop Phoenix stack AND destroy all trace data
make phoenix-reset
```

### Architecture

- **Phoenix** ([http://localhost:6006](http://localhost:6006)): Trace visualization and analysis UI. Receives spans from the OTel collector.
- **OTel Collector** (ports 4317 gRPC, 4318 HTTP): Receives OTLP spans from the gateway and forwards them to Phoenix.

### How It Connects

The gateway reaches the OTel collector via the shared `phoenix-observability-network` Docker network. The gateway's `OTEL_EXPORTER_OTLP_ENDPOINT` is set to `otel-collector:4317`.

If Phoenix is not already running, `make up` now auto-runs `make phoenix-up` to
guarantee the shared network exists before gateway startup.

### Trace Visibility

Every request through the gateway produces spans showing the full 13-middleware chain execution. In Phoenix, you can see:
- Per-middleware latency
- Which middleware layers triggered (DLP flags, rate limit decisions, deep scan results)
- Token substitution timing
- Upstream MCP server response time

### OpenSearch + Dashboards (Optional Compliance/Forensics Profile)

Use this optional profile when you need indexed evidence search and analyst
dashboards in addition to Phoenix traces:

```bash
make opensearch-up
make opensearch-seed
make opensearch-validate
```

Endpoints:

- OpenSearch API: `http://localhost:9200`
- OpenSearch Dashboards: `http://localhost:5601`

This profile re-routes gateway audit JSONL to a shared volume and forwards
records into OpenSearch (`precinct-audit-*`) via Fluent Bit.

---

## 7. Troubleshooting

### SPIRE Stale SVIDs

**Symptom:** Services fail to start or mTLS handshakes fail after a previous unclean shutdown.

**Fix:** `make clean` now clears SPIRE data directories automatically. For a fresh restart:
```bash
make clean && make up
```

Or manually clear the state:
```bash
rm -rf data/spire-server/ data/spire-agent/
make down && make up
```

### SVID Fetch Latency on First Call

**Symptom:** First request through the gateway takes 5-10 seconds or times out.

**Cause:** The SPIRE agent needs to attest and deliver SVIDs on the first call. Subsequent calls use cached SVIDs.

**Fix:** Wait for all health checks to pass (the `--wait` flag in `make up` handles this). If sending manual requests, allow 5-10 seconds after `docker compose ps` shows healthy.

### Docker Workload Attestor Not Matching

**Symptom:** SPIRE entries exist but workloads cannot fetch SVIDs. Only `unix:uid` selectors appear in agent logs.

**Fix:** Ensure two settings in the SPIRE agent configuration:
1. `spire-agent` container must have `pid: host` in `docker-compose.yml` (already configured)
2. Docker workload attestor must have `use_new_container_locator = true` for cgroupv2 (Docker Desktop, modern Linux)

Without both of these, Docker selectors silently fail and only unix selectors (uid/gid) are produced.

### SPIKE Nexus Trust Root Configuration

**Symptom:** SPIKE Nexus fails to start with validation errors.

**Fix:** `SPIKE_TRUST_ROOT_NEXUS` is required (not just `SPIKE_TRUST_ROOT`). Both must be set to the trust domain (`poc.local` for Docker Compose, `precinct.poc` for K8s).

### SPIKE Nexus SPIFFE ID

**Symptom:** SPIKE Nexus cannot authenticate via SPIRE.

**Fix:** The spike-nexus SPIFFE ID must be `/spike/nexus` (not `/ns/spike-system/sa/spike-nexus`). Verify the SPIRE entry matches this pattern.

### SPIKE Has No /healthz Endpoint

**Symptom:** Kubernetes HTTP health probes fail for SPIKE Nexus.

**Cause:** SPIKE requires mTLS on all endpoints, including health checks. The kubelet cannot present SPIFFE client certificates.

**Fix:** Use TCP socket probes for K8s liveness and readiness checks (already configured in the local overlay). For Docker Compose, the healthcheck uses a custom binary that performs a real mTLS connection.

### Rate Limit Keys Persist Between Demo Runs

**Symptom:** Rate limit tests fail or behave differently on subsequent demo runs because counters are not reset.

**Fix:** Rate limit keys persist in KeyDB. Use targeted Lua cleanup for `ratelimit:*` keys instead of `FLUSHALL` (which would destroy session data). The demo script handles this automatically, but for manual cleanup:
```bash
docker exec keydb keydb-cli --scan MATCH 'ratelimit:*' | xargs -r docker exec keydb keydb-cli DEL
```

### Phoenix Network Must Exist Before `make up`

**Symptom:** `make up` fails with "phoenix-observability-network not found".

**Fix:** Start Phoenix first:
```bash
make phoenix-up
make up
```

The gateway container joins the `phoenix-observability-network` to send traces to the OTel collector. If this network does not exist, Docker Compose fails at container creation.

Note: this failure mode is now uncommon because `make up` auto-starts Phoenix when
the network is missing.

### SPIRE Entry Registration Must Happen Before Workloads Start

**Symptom:** SPIKE Nexus or gateway starts before SPIRE entries are registered and cannot fetch SVIDs.

**Fix:** The `spire-entry-registrar` init container must complete before SPIKE or gateway services start. This is enforced by `depends_on: spire-entry-registrar: condition: service_completed_successfully` in `docker-compose.yml`. If manually registering entries, run `make register-spire` before starting dependent services.

### Kubernetes: SPIRE Agent Wrapper for Distroless Images

**Symptom:** SPIRE agent pod fails in K8s because the official `spire-agent:1.10.0` image has no shell.

**Fix:** The local overlay uses a custom wrapper image (`spire-agent-wrapper`) that includes a shell to read the join token from a shared volume. The wrapper calls `/opt/spire/bin/spire-agent` directly. This is built and pushed to the local registry by `make k8s-up`.

### Kubernetes: PSS Violations

**Symptom:** Pods rejected by Pod Security Admission in K8s.

**Fix:** For Docker Desktop local development, the local overlay relaxes PSS to `privileged` on namespaces that need hostPath volumes (spire-system, gateway, tools, spike-system). This is intentional for local dev. Production uses the `restricted` profile.

### Attestation Signatures Must Be Regenerated After Config Changes

**Symptom:** Integration tests fail with signature verification errors after editing `config/tool-registry.yaml`, `config/opa/tool_registry.yaml`, or other attested configuration artifacts. The failure message is often cryptic until you know this pattern.

**Cause:** Each attested config file has an accompanying Ed25519 `.sig` file. Modifying the config invalidates the signature. The signing key is separate from the config file, so the mismatch is not detected at edit time.

**Fix:** Run `make attestation-resign` to regenerate all three attestation files (tool-registry, model-provider-catalog, guard-artifact) in sequence. The `config/tool-registry.yaml` header includes a reminder: "Modifying this file requires running `make attestation-resign`."

### OTel Collector Must Be Running Before Gateway Starts

**Symptom:** Spans are lost during startup. Gateway starts before the OTel Collector is ready.

**Cause:** The Docker Compose `gateway` service does not declare `depends_on` for `otel-collector`. If the collector is not ready when the gateway starts, spans produced during startup are silently dropped.

**Fix:** Add an explicit `depends_on` for `otel-collector` in the gateway service definition. The preferred approach is to start Phoenix first (`make phoenix-up`) before `make up`, which is already the documented order. Note that the OTel gRPC exporter uses a lazy connection -- it does not fail at startup even if the collector is unreachable, which is why lost spans at startup are otherwise silent.

---

## 8. Environment Variables Quick Reference

The gateway is configured via environment variables. The most commonly needed ones are listed here. For the full list, see the `precinct-gateway` service definition in `docker-compose.yml`.

### Gateway Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | Gateway HTTP listen port |
| `UPSTREAM_URL` | `http://mock-mcp-server:8082` | Target MCP server URL (dev). For strict profiles with `MCP_TRANSPORT_MODE=mcp`, this must be `https://...` |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `MCP_TRANSPORT_MODE` | `mcp` | Transport mode: `mcp` (Streamable HTTP) or `proxy` (reverse proxy) |
| `MAX_REQUEST_SIZE_BYTES` | `10485760` | Maximum request body size (10MB) |

### SPIFFE/mTLS

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIFFE_MODE` | `prod` | SPIFFE mode: `dev` (HTTP) or `prod` (mTLS) |
| `SPIFFE_TRUST_DOMAIN` | `poc.local` | SPIFFE trust domain |
| `SPIFFE_LISTEN_PORT` | `9443` | mTLS listen port (prod mode) |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///tmp/spire-agent/public/api.sock` | SPIRE agent workload API socket |

### Strict Profile MCP Transport (Compose + K8s)

Use this set as a baseline when validating production-readiness transport posture:

| Variable | Required Value |
|----------|----------------|
| `ENFORCEMENT_PROFILE` | `prod_standard` or `prod_regulated_hipaa` |
| `SPIFFE_MODE` | `prod` |
| `MCP_TRANSPORT_MODE` | `mcp` |
| `UPSTREAM_URL` | `https://<mcp-upstream>/mcp` |
| `APPROVAL_SIGNING_KEY` | strong non-default key (>=32 chars) |
| `TOOL_REGISTRY_PUBLIC_KEY` | `/config/attestation-ed25519.pub` |
| `OPA_POLICY_PUBLIC_KEY` | `/config/attestation-ed25519.pub` |
| `MODEL_PROVIDER_CATALOG_PUBLIC_KEY` | `/config/attestation-ed25519.pub` |
| `GUARD_ARTIFACT_PATH` | `/config/guard-artifact.bin` |
| `GUARD_ARTIFACT_SHA256` | `8232540100ebde3b5682c2b47d1eee50764f6dadca3842400157061656fc95a3` |
| `GUARD_ARTIFACT_PUBLIC_KEY` | `/config/attestation-ed25519.pub` |

Notes:

- Strict startup fails if `UPSTREAM_URL` is not `https://...` in MCP mode.
- Strict MCP transport fails closed if SPIFFE mTLS upstream transport is not initialized.
- Strict startup fails when signed tool registry/catalog/guard artifact material is missing or invalid.
- Strict OPA reloads require `OPA_POLICY_PUBLIC_KEY`; unsigned or tampered policy changes are rejected and the prior policy remains active.
- Strict tool registry hot-reload rejects unsigned/invalid updates without permissive fallback.
- Keep `UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS` explicit for blue/green/canary identity overlap windows.

### Security Controls

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | (empty) | API key for Groq deep scan guard model. Required for deep scan functionality |
| `GUARD_MODEL_ENDPOINT` | `https://api.groq.com/openai/v1` | Guard model API base URL. See [Guard Model Configuration](#guard-model-configuration) |
| `GUARD_MODEL_NAME` | `meta-llama/llama-prompt-guard-2-86m` | Guard model identifier. See [Guard Model Configuration](#guard-model-configuration) |
| `GUARD_API_KEY` | (empty) | Guard model API key. Falls back to `GROQ_API_KEY` if empty |
| `DEEP_SCAN_TIMEOUT` | `5` | Deep scan API timeout in seconds |
| `DEEP_SCAN_FALLBACK` | `fail_closed` | Behavior when deep scan fails: `fail_closed` or `fail_open` |
| `DLP_INJECTION_POLICY` | (empty) | Override DLP injection action: `block` or `flag`. Default uses YAML config |

### Guard Model Configuration

The guard model provides LLM-based prompt injection detection and step-up risk assessment. It is used by two middleware layers in the security chain:

- **Deep scan** (middleware step 10): Scans request content for prompt injection patterns using the guard model as a classifier.
- **Step-up gating** (middleware step 9): Queries the guard model to assess risk for medium-risk requests that require step-up verification before proceeding.

#### Default Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARD_MODEL_ENDPOINT` | `https://api.groq.com/openai/v1` | Base URL for the guard model API (any OpenAI-compatible chat completions endpoint) |
| `GUARD_MODEL_NAME` | `meta-llama/llama-prompt-guard-2-86m` | Model identifier sent to the guard model endpoint |
| `GUARD_API_KEY` | (empty) | API key for the guard model provider. Falls back to `GROQ_API_KEY` if not set |
| `GROQ_API_KEY` | (empty) | Legacy/fallback API key. Used when `GUARD_API_KEY` is not set |

#### How Keys Are Loaded

The guard model API key is resolved at gateway startup using a two-tier lookup:

1. **SPIKE secret store (preferred):** When `SPIKE_NEXUS_URL` is configured, the gateway attempts to fetch the key from SPIKE Nexus via SPIFFE mTLS (reference `groq-api-key`). The `spike-secret-seeder` init container seeds this secret from `.env` into SPIKE during stack startup. The gateway retries up to 15 times (2-second intervals) to allow the seeder to complete.
2. **Environment variable fallback:** If SPIKE is unavailable or returns an empty value, the gateway falls back to `GUARD_API_KEY`, then `GROQ_API_KEY` from the environment.

When a real API key is loaded from SPIKE and the current endpoint points to the mock guard model, the gateway automatically switches to the real Groq API endpoint.

#### Groq Dependency Notice

The default model (`meta-llama/llama-prompt-guard-2-86m`) runs on Groq's PREVIEW tier, which carries no SLA. Groq has historically deprecated guard models on roughly an annual cadence. The gateway code is provider-agnostic -- any OpenAI-compatible chat completions endpoint can be substituted without code changes.

#### How to Swap Providers

Set `GUARD_MODEL_ENDPOINT` and `GUARD_MODEL_NAME` to point at any OpenAI-compatible chat completions API. Examples:

| Provider | `GUARD_MODEL_ENDPOINT` | `GUARD_MODEL_NAME` |
|----------|------------------------|--------------------|
| Groq (default) | `https://api.groq.com/openai/v1` | `meta-llama/llama-prompt-guard-2-86m` |
| Self-hosted vLLM | `http://vllm-host:8000/v1` | `meta-llama/Llama-Prompt-Guard-2-86M` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` (or any suitable classifier) |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<deployment>/v1` | (deployment name) |

Set `GUARD_API_KEY` to the corresponding provider's API key.

#### Behavior When Guard Model Is Unavailable

The behavior depends on the enforcement profile (`ENFORCEMENT_PROFILE`):

| Profile | Behavior | Effect |
|---------|----------|--------|
| `dev` (default) | Fails open | Step-up gating allows medium-risk requests through without guard model verification |
| `prod_standard` / `prod_regulated_hipaa` | Fails closed | Step-up gating denies requests when the guard model cannot be reached |

Deep scan timeout behavior is controlled independently by `DEEP_SCAN_FALLBACK` (`fail_closed` by default).

#### Verification

After starting the stack, confirm the guard model key was loaded:

```bash
docker compose logs precinct-gateway | grep "guard model"
```

Expected output (one of):

- `guard model API key loaded from SPIKE` -- key was fetched from SPIKE Nexus (preferred path)
- `no guard model API key available from SPIKE or environment; step-up guard will degrade to fail-open` -- no key found; guard model is inactive

### Rate Limiting

| Variable | Default (Compose) | Description |
|----------|-------------------|-------------|
| `RATE_LIMIT_RPM` | `60` | Requests per minute per agent. Code default is 600; compose default is 60 for demo |
| `RATE_LIMIT_BURST` | `10` | Burst bucket size. Code default is larger; compose default is 10 for demo |

### Data Stores

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYDB_URL` | `redis://keydb:6379` | KeyDB connection URL. Auto-converts to `rediss://keydb:6380` in prod mode |
| `SPIKE_NEXUS_URL` | `https://spike-nexus:8443` | SPIKE Nexus API URL for token redemption |
| `AUDIT_LOG_PATH` | `/tmp/audit.jsonl` | Path for structured JSON audit log output |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `otel-collector:4317` | OpenTelemetry collector gRPC endpoint |
| `OTEL_SERVICE_NAME` | `precinct-gateway` | Service name in traces |
| `AUDIT_LOG_PATH` | `/tmp/audit.jsonl` | Default audit sink path. OpenSearch profile overrides to `/var/log/gateway/audit.jsonl` |

Strict observability evidence gate:

- Non-strict (default): demos continue with warnings when Phoenix/collector is unavailable.
- Strict mode (`DEMO_STRICT_OBSERVABILITY=1`): demos fail if telemetry sinks are unavailable or trace/audit evidence files are missing.
- Validation target: `make observability-evidence-gate-validate`.

### Dev vs Strict Operating Procedures

Docker Compose dev mode:

```bash
docker compose -f docker-compose.yml up -d
```

Docker Compose strict hardening mode:

```bash
export STRICT_UPSTREAM_URL="https://<strict-upstream>/mcp"
export APPROVAL_SIGNING_KEY="<strong-signing-key-32+>"
export ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/ops/sa/gateway-admin"
export UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/tools/sa/mcp-tool"
export KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/data/sa/keydb"
docker compose --profile strict -f docker-compose.yml -f docker-compose.strict.yml up -d
```

The strict override replaces the gateway's inherited dev/demo runtime state from
`docker-compose.yml`. A rendered strict config should expose only `9443:9443`
for `precinct-gateway` and should not include
`ALLOW_INSECURE_DEV_MODE`, `ALLOW_NON_LOOPBACK_DEV_BIND`,
`DEMO_RUGPULL_ADMIN_ENABLED`, `DEV_LISTEN_HOST=0.0.0.0`,
`GUARD_MODEL_ENDPOINT=http://mock-guard-model:8080/openai/v1`, or
`MODEL_PROVIDER_ENDPOINT_GROQ=http://mock-guard-model:8080/openai/v1/chat/completions`.

Strict compose mode expects these files in `./config`:

- `attestation-ed25519.pub`
- `tool-registry.yaml` and `tool-registry.yaml.sig`
- `model-provider-catalog.v2.yaml` and `model-provider-catalog.v2.yaml.sig`
- `guard-artifact.bin` and `guard-artifact.bin.sig`

This strict-only overlay hardens the gateway transport/profile, but it does not add
the extra SPIKE keepers needed for release recovery posture. For release-facing
compose, layer `docker-compose.prod-intent.yml` on top of the strict overlay.

Compose production-intent supply-chain mode (release gate path):

```bash
make compose-production-intent-preflight
export PROD_SPIKE_NEXUS_SHAMIR_THRESHOLD="2"
export PROD_SPIKE_NEXUS_SHAMIR_SHARES="3"
docker compose --profile strict \
  --env-file config/compose-production-intent.env \
  -f docker-compose.yml \
  -f docker-compose.strict.yml \
  -f docker-compose.prod-intent.yml up -d
```

Release-gate expectation:

- `go vet ./...` must pass cleanly before release sign-off. `make lint` enforces this gate directly when `golangci-lint` is unavailable, and operators may run `go vet ./...` standalone when triaging release blockers.

Production-intent compose requirements:

- Required services must set `pull_policy: always` and use digest-pinned immutable image refs from `config/compose-production-intent.env`.
- Provenance/signature policy requirements are codified in `config/compose-production-intent-policy.json`.
- SPIKE keeper recovery defaults to `2-of-3` with three keeper peers; only the local demo/dev paths may remain `1-of-1`.
- Deterministic validation command: `make compose-production-intent-validate` (includes supply-chain and egress-control negative-path failure tests).

Migration notes:

- Dev/demo path remains unchanged (`docker-compose.yml`, `make demo-compose`).
- Strict hardening mode is a local/runtime validation layer; release-facing compose is explicit and separate (`docker-compose.prod-intent.yml` + lock/policy files) and defaults SPIKE keeper recovery to `2-of-3`.
- Do not reuse dev/demo local tags for production-intent releases.
- Validate the split between demo and release keeper profiles with `make spike-shamir-validate`.

K8s dev/local mode:

```bash
kustomize build deploy/terraform/overlays/local | kubectl apply -f -
```

Validate the SPIKE recovery posture before release sign-off:

```bash
make spike-shamir-validate
```

K8s strict production-intent mode:

```bash
make k8s-overlay-digest-validate OVERLAYS="staging prod"
kustomize build deploy/terraform/overlays/staging | kubectl apply -f -
# or
kustomize build deploy/terraform/overlays/prod | kubectl apply -f -
```

The strict overlays now consume workflow-managed `digest:` pins in each
`kustomization.yaml`. The repo-root `.github/workflows/promote.yaml` workflow
rewrites those digests with `kustomize edit set image ...@sha256:<digest>` and
validates the rendered target overlay before any optional commit.

Strict runtime wiring validation (fail-fast):

```bash
make strict-runtime-validate
```

### External-App Full-Port Release Gate (Runbook Policy)

External-app promotion decisions must reference accepted framework-closure evidence and the latest upstream source baseline.

Enforced references:

- Readiness epic: `RFA-l6h6.7`
- Final strict conformance campaign: `RFA-l6h6.7.7`
- External-app execution story: `RFA-l6h6.6.10` (accepted/closed)
- Framework-gap closure epic: `RFA-l6h6.6.17` (accepted/closed)
- Post-gap reassessment: `RFA-l6h6.6.17.1` (accepted/closed)
- Latest-source closure chain: `RFA-pnxr`, `RFA-ysa5`, `RFA-oo21`, `RFA-t1hb`, `RFA-6mp8`, `RFA-655e` (accepted/closed)
- Latest-source final decision artifact: latest external-app final decision artifact in `docs/security/`

Required operator checks before any external-app promotion/reassessment:

```bash
make strict-runtime-validate
make production-readiness-validate
make readiness-state-validate
nd show oc-ko5 --json
nd show oc-36m --json
cd <upstream-reference-app-repo> && git rev-parse HEAD
```

Historical note: the `RFA-*` identifiers in this section are archival beads-era
campaign IDs preserved for audit context. The active tracker checks above use the
current `nd` IDs referenced by `docs/status/production-readiness-state.json`.

Current gate interpretation:
- **GO past framework-closure gate** when `RFA-l6h6.7.7`, `RFA-l6h6.6.10`, and `RFA-l6h6.6.17.1` are accepted/closed and validation evidence is current.
- **GO for latest-source external-app cycle** when latest-source closure chain stories are accepted/closed and no unresolved follow-up bugs remain.
- **NO-GO** if any gate story is open/rejected/blocked, validation evidence is stale, or latest-source follow-up bugs are unresolved.

### Cloud Adaptation Playbooks

For managed-cloud adaptation beyond local Docker Desktop K8s:

- `docs/architecture/cloud-adaptation-playbooks.md` (AWS EKS + EKS/Fargate, GKE, AKS)
- `docs/architecture/cloudflare-workers-compensating-controls.md` (Workers-specific compensating controls)
- `docs/architecture/non-k8s-cloud-adaptation-guide.md` (runtime-agnostic control mapping)
- `docs/operations/managed-cloud-bootstrap-prerequisites.md` (managed staging bootstrap/access prerequisite contract + handoff template)

### GHCR Fail-Closed Live Signature Path (What It Means)

`compose-production-intent-preflight` supports a strict mode where live signature
verification is enforced at release time:

```bash
COMPOSE_PROD_VERIFY_SIGNATURE=1 make compose-production-intent-preflight
```

In fail-closed mode, image verification must succeed against the registry/signing
metadata for required production-intent images. If auth/token retrieval or signature
verification fails, release validation fails (no silent skip).

Required credential inputs for live signature mode:

- `COMPOSE_PROD_REGISTRY_USERNAME`
- `COMPOSE_PROD_REGISTRY_TOKEN`

Reference docs:

- `docs/security/compose-signature-prerequisite-contract.md`
- `docs/operations/runbooks/compose-signature-credential-injection.md`
- `make compose-production-intent-preflight-signature-prereqs` (deterministic missing-prerequisite validator)

For local/dev without registry credentials, non-strict mode remains available for
workflow continuity, but that is not equivalent evidence for cloud release sign-off.

---

## 9. Make Targets Quick Reference

| Target | Description |
|--------|-------------|
| `make help` | Show all documented targets |
| `make compose-verify` | Verify compose third-party images and Dockerfile base images are digest-pinned |
| `make k8s-overlay-digest-validate` | Render staging/prod overlays and fail if gateway/tools workloads violate the Gatekeeper digest policy |
| `make spike-shamir-validate` | Verify local demo keeps 1-of-1 recovery isolated while strict compose/EKS configs require multi-share keeper recovery |
| `make compose-production-intent-preflight` | Validate production-intent compose image lock + provenance policy wiring |
| `make compose-production-intent-preflight-signature-prereqs` | Validate fail-closed live-signature credential prerequisite behavior |
| `make compose-production-intent-validate` | Run production-intent compose gate with deterministic supply-chain + egress negative-path failure tests |
| `make operations-backup-restore-drill` | Execute operational backup/restore drill and publish latest drill artifacts |
| `make operations-readiness-validate` | Validate operations readiness pack (runbooks, drill artifacts, SLO ownership) |
| `make managed-cloud-bootstrap-prereqs-validate` | Validate managed-cloud bootstrap prerequisites and deterministic fail-fast preflight behavior |
| `make framework-taxonomy-mappings-validate` | Validate MITRE ATLAS + OWASP Agentic Top 10 mapping coverage for audit signal keys |
| `make up` | Start Docker Compose stack (waits for all services healthy) |
| `make down` | Stop Docker Compose stack |
| `make clean` | Full cleanup (containers, volumes, build artifacts) |
| `make test` | Run all tests (unit + tagged integration + OPA) |
| `make lint` | Run linters |
| `make build` | Build gateway container image |
| `make demo-compose` | Run E2E demo against Docker Compose |
| `make demo-compose-strict-observability` | Run E2E compose demo with strict observability evidence enforcement |
| `make demo-k8s` | Run E2E demo against Kubernetes |
| `make phoenix-up` | Start Phoenix + OTel collector |
| `make phoenix-down` | Stop Phoenix (preserves traces) |
| `make phoenix-reset` | Stop Phoenix + destroy trace data |
| `make opensearch-up` | Start OpenSearch + Dashboards + audit forwarder |
| `make opensearch-seed` | Seed OpenSearch index template and dashboard objects |
| `make opensearch-validate` | Validate OpenSearch profile health and template wiring |
| `make opensearch-down` | Stop OpenSearch profile (preserves indexed data) |
| `make opensearch-reset` | Stop OpenSearch profile + destroy indexed data |
| `make observability-up` | Start both observability backends (Phoenix + OpenSearch) |
| `make observability-down` | Stop both observability backends (preserves data) |
| `make observability-reset` | Destroy all observability backend data |
| `make k8s-up` | Deploy full stack to local K8s (syncs config, builds, deploys) |
| `make k8s-sync-config` | Sync K8s overlay gateway config from canonical config/ source |
| `make k8s-check-config` | Check K8s overlay gateway config for drift (CI use) |
| `make k8s-opensearch-up` | Deploy local K8s stack plus OpenSearch observability extension |
| `make k8s-opensearch-down` | Remove OpenSearch extension resources from local K8s deployment |
| `make k8s-down` | Teardown local K8s deployment |
| `make k8s-prereqs` | Install K8s CRD prerequisites (Gatekeeper, sigstore) |
| `make k8s-registry` | Start local container registry |
| `make register-spire` | Register SPIRE workload entries (Docker Compose) |
| `make k8s-register-spire` | Register SPIRE workload entries (K8s) |
| `make ci` | Full CI pipeline (lint + test + build) |
| `make benchmark` | Run performance benchmarks |
| `make security-scan` | Run security scans and emit artifact bundle (`build/security-scan/latest`) |
| `make security-scan-strict` | Run security scans in strict mode (fail on skipped/failed scanners) |
| `make security-scan-validate` | Validate required security evidence artifacts + manifest hashes |
| `make readiness-state-validate` | Validate readiness docs/state snapshot against live `nd` status and external-app gate dependency |
| `make production-readiness-validate` | Enforce strict security scan evidence gate for production readiness |
| `make ci-gate-parity-validate` | Validate manual-only CI workflow policy (strict readiness + demo coverage + manual K8s policy gate) |
| `make observability-evidence-gate-validate` | Validate strict/non-strict observability evidence gate behavior |
| `make compliance-report` | Generate compliance report |
| `make test-unit` | Run unit tests (Go packages + non-tagged suites) |
| `make test-integration` | Run integration tests |
| `make test-opa` | Run OPA policy tests |
| `make test-e2e` | Run the full E2E demo suite (Compose + K8s) |
| `make validate-setup-time` | Validate 30-minute setup claim |
| `make gdpr-delete` | GDPR right-to-deletion for a SPIFFE ID |
