# Configuration Reference

This document is the single reference for all environment variables, configuration files,
and policy customization options for the PRECINCT Gateway and its supporting infrastructure.

All defaults listed here are verified against source code in `internal/gateway/config.go`
and runtime values in `docker-compose.yml`.

---

## Table of Contents

1. [Gateway Environment Variables](#1-gateway-environment-variables)
2. [SPIRE Environment Variables](#2-spire-environment-variables)
3. [SPIKE Environment Variables](#3-spike-environment-variables)
4. [Phoenix / OpenTelemetry / OpenSearch Variables](#4-phoenix--opentelemetry--opensearch-variables)
5. [MCP-UI Environment Variables](#5-mcp-ui-environment-variables)
6. [Configuration Files](#6-configuration-files)
7. [OPA Policy Structure](#7-opa-policy-structure)
8. [DLP Policy Configuration](#8-dlp-policy-configuration)
9. [Escalation Thresholds](#9-escalation-thresholds)
10. [Data Source Registry](#10-data-source-registry)
11. [Port Adapter Environment Variables](#11-port-adapter-environment-variables)
12. [SPIFFE ID Schema](#12-spiffe-id-schema)

---

## 1. Gateway Environment Variables

These variables configure the `precinct-gateway` service. Source: `internal/gateway/config.go`
function `ConfigFromEnv()`.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | HTTP listen port for the gateway |
| `UPSTREAM_URL` | `http://host.docker.internal:8081/mcp` | Backend MCP server URL. Docker Compose overrides to `http://mock-mcp-server:8082` for dev. In strict profiles with `MCP_TRANSPORT_MODE=mcp`, this must be `https://...` (startup fails otherwise) |
| `MAX_REQUEST_SIZE_BYTES` | `10485760` (10 MB) | Maximum request body size in bytes |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `AUDIT_LOG_PATH` | `/var/log/gateway/audit.jsonl` | Path to the JSONL audit log file |
| `SPIFFE_MODE` | `prod` | SPIFFE operating mode: `dev` (HTTP, no mTLS) or `prod` (HTTPS with SPIRE mTLS) |
| `SPIFFE_TRUST_DOMAIN` | `poc.local` | SPIFFE trust domain for workload identity |
| `SPIFFE_LISTEN_PORT` | `9443` | HTTPS listen port when `SPIFFE_MODE=prod` |
| `SPIFFE_ENDPOINT_SOCKET` | _(none)_ | SPIRE Workload API socket URI (e.g., `unix:///tmp/spire-agent/public/api.sock`). This is the only SPIRE socket variable the gateway reads; `SPIRE_AGENT_SOCKET` (set in docker-compose.yml) is not consumed by gateway code |
| `MCP_TRANSPORT_MODE` | `mcp` | Transport mode: `mcp` (MCP Streamable HTTP) or `proxy` (reverse proxy, backward compatible) |
| `ALLOWED_BASE_PATH` | Current working directory | Base directory for OPA path-based access control (read/grep tools). All file access is restricted to paths under this directory |

SPIFFE identity mode behavior:

- `SPIFFE_MODE=dev`: identity is read from `X-SPIFFE-ID` header (development compatibility only).
- `SPIFFE_MODE=prod`: identity is extracted from client mTLS certificate `spiffe://` URI SAN; `X-SPIFFE-ID` headers are ignored.

### Enforcement Profiles

| Variable | Default | Description |
|----------|---------|-------------|
| `ENFORCEMENT_PROFILE` | `dev` | Runtime profile bundle: `dev`, `prod_standard`, `prod_regulated_hipaa` |
| `ENFORCE_MODEL_MEDIATION_GATE` | `true` | Enforces mediated model egress (`direct`/`bypass` denied) |
| `ENFORCE_HIPAA_PROMPT_SAFETY_GATE` | `true` | Enables HIPAA prompt safety deny checks when HIPAA profile policy is active |
| `MODEL_POLICY_INTENT_PREPEND_ENABLED` | `false` | Prepends compact policy-intent guidance to OpenAI-compatible model messages. Strict production-intent overlays set this to `true` |
| `PROFILE_METADATA_EXPORT_PATH` | _(empty)_ | Optional path to write active profile metadata as JSON at startup |
| `APPROVAL_SIGNING_KEY` | _(empty)_ | HMAC signing key for step-up approval capability tokens. In strict profiles (`prod_standard`, `prod_regulated_hipaa`), startup fails if missing, too short, or a known weak/default value |
| `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` | _(empty)_ | Comma-separated admin SPIFFE IDs allowed to reach `/admin/*`. No implicit defaults are applied; in strict profiles startup fails if this is missing or empty |
| `UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS` | _(empty)_ | Comma-separated upstream SPIFFE IDs allowed for mTLS peer pinning. When empty in strict profiles, secure defaults are auto-applied |
| `KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS` | _(empty)_ | Comma-separated KeyDB SPIFFE IDs allowed for mTLS peer pinning. When empty in strict profiles, secure defaults are auto-applied |

### Phase 3 Control Plane Wiring

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPABILITY_REGISTRY_V2_PATH` | _(empty)_ | Optional path to capability registry v2 used by tool-plane policy enforcement (`/v1/tool/execute`) |
| `MODEL_PROVIDER_CATALOG_PATH` | _(empty)_ | Path to model provider catalog v2 (provider endpoints/models/residency/fallbacks). **Required in strict profiles** |
| `MODEL_PROVIDER_CATALOG_PUBLIC_KEY` | _(empty)_ | PEM public key path for model provider catalog signature verification (`.sig`). **Required in strict profiles** |
| `GUARD_ARTIFACT_PATH` | _(empty)_ | Local path to guard model artifact for startup integrity verification. **Required in strict profiles** |
| `GUARD_ARTIFACT_SHA256` | _(empty)_ | Expected SHA-256 digest for `GUARD_ARTIFACT_PATH`. **Required in strict profiles** |
| `GUARD_ARTIFACT_SIGNATURE_PATH` | `<GUARD_ARTIFACT_PATH>.sig` when unset | Signature path for guard artifact verification |
| `GUARD_ARTIFACT_PUBLIC_KEY` | _(empty)_ | PEM public key path for guard artifact signature verification. **Required in strict profiles** |

Wiring behavior:

- When `MODEL_PROVIDER_CATALOG_PATH` is set, the gateway loads the catalog at startup and applies endpoint/model/residency policy to model egress.
- In strict profiles, provider catalog signature verification is mandatory. Unsigned or invalid catalog signatures fail startup.
- In strict profiles, guard artifact digest/signature verification is mandatory and fail-closed.
- In `dev`, missing/mismatched guard artifact digest/signature is logged as warn-only for local development.

Profile bundles and required controls:

| Profile | Startup Gate Mode | Required Runtime Controls |
|---------|-------------------|---------------------------|
| `dev` | permissive | Portable defaults; no strict startup fail on production invariants |
| `prod_standard` | strict | `SPIFFE_MODE=prod`, `MCP_TRANSPORT_MODE=mcp`, `UPSTREAM_URL=https://...`, `ENFORCE_MODEL_MEDIATION_GATE=true`, strong `APPROVAL_SIGNING_KEY`, non-empty `TOOL_REGISTRY_CONFIG_PATH`, `TOOL_REGISTRY_PUBLIC_KEY`, `MODEL_PROVIDER_CATALOG_PATH`, `MODEL_PROVIDER_CATALOG_PUBLIC_KEY`, `GUARD_ARTIFACT_PATH`, `GUARD_ARTIFACT_SHA256`, `GUARD_ARTIFACT_PUBLIC_KEY` |
| `prod_regulated_hipaa` | strict | `prod_standard` controls + `ENFORCE_HIPAA_PROMPT_SAFETY_GATE=true` |

Migration notes for approval signing key hardening:

- Strict profiles now fail fast at startup when `APPROVAL_SIGNING_KEY` is missing/weak. Existing deployments that relied on implicit fallback behavior must set this variable before enabling strict profiles.
- Strict profiles now fail fast at startup when `ADMIN_AUTHZ_ALLOWED_SPIFFE_IDS` is missing/empty. Dev/test admin access must be granted explicitly in configuration instead of relying on baked-in principals.
- Use a high-entropy key with at least 32 characters and store it in your secret manager/Kubernetes Secret.
- Dev profile behavior is intentionally bounded: when unset, the gateway generates an ephemeral process-local key at startup (not a static default). This is for local workflows only and tokens are not stable across restarts.

Strict profile defaults for SPIFFE peer identity pinning:

- Upstream (`UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS` when unset):
  - `spiffe://<trust-domain>/ns/tools/sa/mcp-tool`
  - `spiffe://<trust-domain>/tools/docker-mcp-server/dev`
- KeyDB (`KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS` when unset):
  - `spiffe://<trust-domain>/keydb`
  - `spiffe://<trust-domain>/ns/data/sa/keydb`

Strict MCP transport invariants:

- In strict profiles, startup fails if `UPSTREAM_URL` is empty, invalid, or not `https://...` while `MCP_TRANSPORT_MODE=mcp`.
- In strict profiles, MCP transport initialization fails closed unless SPIFFE mTLS transport wiring is active (no fallback to implicit default HTTP client semantics).
- In strict profiles, tool hash verification is fail-closed. If observed `tools/list` hashes are unavailable, missing, or refresh fails, `tools/call` is denied with explicit `reason_code` values (`observed_hash_unavailable`, `observed_hash_missing`, `observed_hash_refresh_failed`).
- In strict overlays, `MODEL_POLICY_INTENT_PREPEND_ENABLED=true` injects compact policy-intent XML for model calls. This guidance is advisory only; runtime policy enforcement remains authoritative.
- Policy-intent projection is safe for model context: it contains sanitized intent labels only (allowed/prohibited classes + escalation hints) and never exposes internal policy code or Rego source.

Policy-intent projection schema (compact XML v1):

```xml
<policy_intent version="1">
  <actor>spiffe://...</actor>
  <model provider="groq" name="..." residency="us" risk="low" compliance="standard" mediation="mediated"/>
  <allowed><item>mediated_model_call</item></allowed>
  <prohibited><item>direct_egress</item><item>policy_bypass</item>...</prohibited>
  <escalation>request_step_up_approval_when_action_is_high_risk_or_uncertain</escalation>
  <authority>advisory_only_runtime_policy_enforcement_remains_authoritative</authority>
</policy_intent>
```

Mission-bound model mediation inputs:

- The OpenAI-compatible mediated route also accepts optional mission-bound request
  metadata so narrow-purpose agents can be kept inside a declared business/task
  scope.
- These controls are request-scoped and additive. If omitted, prior model-egress
  behavior remains unchanged.
- Supported request headers:
  - `X-Agent-Purpose`
  - `X-Mission-Boundary-Mode`
  - `X-Mission-Allowed-Intents`
  - `X-Mission-Allowed-Topics`
  - `X-Mission-Blocked-Topics`
  - `X-Mission-Out-Of-Scope-Action`
  - `X-Mission-Out-Of-Scope-Message`
- Supported runtime outcomes:
  - `deny`: fail closed with an explicit model-plane reason code.
  - `rewrite` / `handoff`: return a synthetic safe assistant response without
    calling the upstream provider.
- `MODEL_POLICY_INTENT_PREPEND_ENABLED` may project sanitized mission guidance
  into the prompt, but that projection is advisory only. Gateway runtime policy
  remains authoritative.

Backward-compatibility behavior:

- In `dev`, empty peer-identity allowlists preserve permissive trust-domain behavior for local workflows.
- In `dev` compatibility mode, proxy paths without an observed-hash refresher may still allow `tools/call` with `hash_verified=false`. Production-intent profiles must not rely on this path.
- In strict profiles, pinning is fail-closed by default (auto defaults or explicit env allowlists).
- Multi-instance/blue-green deployments should provide multiple IDs in the allowlist (comma-separated) so overlap windows do not break mTLS.

Example explicit allowlists:

```bash
export UPSTREAM_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/tools/sa/mcp-tool,spiffe://precinct.poc/ns/tools/sa/mcp-tool-canary"
export KEYDB_AUTHZ_ALLOWED_SPIFFE_IDS="spiffe://precinct.poc/ns/data/sa/keydb,spiffe://precinct.poc/ns/data/sa/keydb-blue"
```

### Guard Model (Deep Scan)

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | _(required for deep scan)_ | API key for Groq inference. Also serves as fallback for `GUARD_API_KEY` |
| `GUARD_MODEL_ENDPOINT` | `https://api.groq.com/openai/v1` | Base URL for the guard model API. Allows pointing to any OpenAI-compatible endpoint |
| `GUARD_MODEL_NAME` | `meta-llama/llama-prompt-guard-2-86m` | Model identifier for the guard model |
| `GUARD_API_KEY` | Falls back to `GROQ_API_KEY` | API key for the guard model endpoint. Set separately when using a non-Groq provider |
| `DEEP_SCAN_TIMEOUT` | `5` | Guard model API timeout in seconds |
| `DEEP_SCAN_FALLBACK` | `fail_closed` | Behavior on guard model timeout or error: `fail_closed` (block) or `fail_open` (allow) |

### DLP

| Variable | Default | Description |
|----------|---------|-------------|
| `DLP_INJECTION_POLICY` | _(empty -- uses YAML config)_ | Override DLP injection policy: `block` or `flag`. When empty, the value from `config/risk_thresholds.yaml` is used. See [DLP Policy Configuration](#8-dlp-policy-configuration) for details |
| `UNKNOWN_DATA_SOURCE_POLICY` | `flag` | Controls handling of unregistered data sources: `"flag"` (allow with audit flag, default), `"block"` (deny with HTTP 403), `"allow"` (allow silently). Applies when a tool references a data source URI not present in the data source registry |

### Rate Limiting

| Variable | Default (code) | Default (docker-compose) | Description |
|----------|----------------|--------------------------|-------------|
| `RATE_LIMIT_RPM` | `600` | `60` | Requests per minute per SPIFFE ID. Docker Compose uses a lower value for demo burst testing |
| `RATE_LIMIT_BURST` | `100` | `10` | Burst allowance above the sustained rate. Docker Compose uses a smaller bucket for demo |

### Circuit Breaker

| Variable | Default | Description |
|----------|---------|-------------|
| `CIRCUIT_FAILURE_THRESHOLD` | `5` | Consecutive upstream failures before the circuit opens |
| `CIRCUIT_RESET_TIMEOUT` | `30` | Seconds the circuit stays open before transitioning to half-open |
| `CIRCUIT_SUCCESS_THRESHOLD` | `2` | Consecutive successes in half-open state before the circuit closes |

### Response Firewall

| Variable | Default | Description |
|----------|---------|-------------|
| `HANDLE_TTL` | `300` (5 minutes) | TTL in seconds for response firewall data handles. Handles expire after this duration |

### Approval Capability

| Variable | Default | Description |
|----------|---------|-------------|
| `APPROVAL_SIGNING_KEY` | _(empty)_ | Signing key for approval capability tokens. Required and validated in strict profiles; optional in `dev` (ephemeral process key generated when unset) |
| `APPROVAL_DEFAULT_TTL_SECONDS` | `600` (10 minutes) | Default TTL for newly issued approval capability tokens |
| `APPROVAL_MAX_TTL_SECONDS` | `3600` (1 hour) | Maximum allowed TTL for approval capability tokens |

### Session Persistence (KeyDB)

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYDB_URL` | _(empty)_ | KeyDB/Redis connection URL. Use `redis://host:6379` in dev mode; auto-converts to `rediss://host:6380` in `SPIFFE_MODE=prod` |
| `KEYDB_POOL_MIN` | `5` | Minimum idle connections in the KeyDB connection pool |
| `KEYDB_POOL_MAX` | `20` | Maximum connections in the KeyDB connection pool |
| `SESSION_TTL` | `3600` (1 hour) | Session TTL in seconds |

### OPA Policy Engine

| Variable | Default | Description |
|----------|---------|-------------|
| `OPA_POLICY_DIR` | `/config/opa` | Directory containing OPA Rego policies and data files |
| `OPA_POLICY_PATH` | `/config/opa/mcp_policy.rego` | Path to the main OPA authorization policy file |
| `TOOL_REGISTRY_CONFIG_PATH` | `/config/tool-registry.yaml` | Path to the tool registry YAML with SHA-256 hashes |
| `OAUTH_RESOURCE_SERVER_CONFIG_PATH` | `/config/oauth-resource-server.yaml` when present | Path to the OAuth resource-server YAML used for bearer JWT validation (`issuer`, `audience`, `jwks_url`, optional `required_scopes`, `clock_skew_seconds`, `cache_ttl_seconds`) |
| `TOOL_REGISTRY_PUBLIC_KEY` | _(empty)_ | Path to PEM public key for tool registry attestation. Empty is allowed only in `dev`; strict profiles require this value and reject unsigned reload/startup artifacts |
| `OPA_POLICY_PUBLIC_KEY` | _(empty)_ | Path to PEM public key for OPA policy reload attestation. Empty is allowed only in `dev`; strict profiles require this value and reject unsigned or tampered OPA reloads |
| `DESTINATIONS_CONFIG_PATH` | `/config/destinations.yaml` | Path to the destination allowlist for step-up gating |
| `RISK_THRESHOLDS_PATH` | `/config/risk_thresholds.yaml` | Path to risk thresholds and DLP policy YAML |
| `UI_CAPABILITY_GRANTS_PATH` | `/config/opa/ui_capability_grants.yaml` | Path to UI capability grants YAML |
| `UI_CONFIG_PATH` | `/config/ui.yaml` | Path to MCP-UI configuration YAML |

### SPIKE Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `SPIKE_NEXUS_URL` | _(empty)_ | SPIKE Nexus HTTPS URL for secret token redemption via mTLS (e.g., `https://spike-nexus:8443`) |

### OpenTelemetry

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty -- no-op)_ | OTLP gRPC endpoint for trace export. When empty, tracing is disabled |
| `OTEL_SERVICE_NAME` | `precinct-gateway` | Service name in emitted traces |

### MCP Transport Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_PROBE_TIMEOUT` | `5` | Per-probe timeout in seconds for MCP transport auto-detection |
| `MCP_DETECT_TIMEOUT` | `15` | Overall detection timeout in seconds for MCP transport auto-detection |
| `MCP_REQUEST_TIMEOUT` | `30` | Per-request timeout in seconds for MCP JSON-RPC calls |

---

## 2. SPIRE Environment Variables

SPIRE Server and Agent are configured primarily through HCL config files in
`config/spire/`. The key configuration values are:

### SPIRE Server (`config/spire/server.conf`)

| Setting | Value | Description |
|---------|-------|-------------|
| `bind_address` | `0.0.0.0` | gRPC listen address |
| `bind_port` | `8081` | gRPC listen port for agent registration |
| `trust_domain` | `poc.local` | SPIFFE trust domain |
| `data_dir` | `/opt/spire/data` | Persistent data directory (SQLite datastore) |
| Health check port | `8080` | Health check listener (`/live` and `/ready` paths) |

### SPIRE Agent (`config/spire/agent.conf`)

| Setting | Value | Description |
|---------|-------|-------------|
| `server_address` | `spire-server` | SPIRE server hostname |
| `server_port` | `8081` | SPIRE server gRPC port |
| `socket_path` | `/tmp/spire-agent/public/api.sock` | Workload API socket path |
| `trust_domain` | `poc.local` | Must match server trust domain |
| `insecure_bootstrap` | `true` | Development only -- skip bootstrap certificate verification |
| WorkloadAttestor | `docker` + `unix` | Docker attestor with `use_new_container_locator=true` (required for cgroupv2) |

### Docker Compose Requirements

- **`pid: host`** on `spire-agent` -- required for Docker workload attestor to resolve PIDs across containers via `SO_PEERCRED`
- **Docker socket mount** (`/var/run/docker.sock`) -- required for Docker label-based workload attestation
- **`use_new_container_locator = true`** -- required for cgroupv2 (Docker Desktop, modern Linux)

---

## 3. SPIKE Environment Variables

SPIKE components (Nexus, Keeper, Bootstrap, Secret Seeder) use the following
environment variables. Source: `docker-compose.yml` service definitions.

### SPIKE Nexus

| Variable | Value | Description |
|----------|-------|-------------|
| `SPIKE_NEXUS_TLS_PORT` | `:8443` | TLS listen port (format includes colon prefix) |
| `SPIKE_NEXUS_BACKEND_STORE` | `sqlite` | Backend store type: `memory` or `sqlite` |
| `SPIKE_NEXUS_DATA_DIR` | `/opt/spike/data` | Data directory for SQLite (AES-256-GCM encrypted) |
| `SPIKE_NEXUS_KEEPER_PEERS` | `https://spike-keeper-1:8443` (local demo) / `https://spike-keeper-1:8443,https://spike-keeper-2:8443,https://spike-keeper-3:8443` (production-intent compose) | Comma-separated list of Keeper URLs for Shamir recovery |
| `SPIKE_NEXUS_SHAMIR_THRESHOLD` | `1` (local demo) / `2` (production-intent compose, EKS) | Minimum Keeper shards needed for root key reconstruction |
| `SPIKE_NEXUS_SHAMIR_SHARES` | `1` (local demo) / `3` (production-intent compose, EKS) | Total Shamir shards; release-facing configs now require multi-share recovery |
| `SPIKE_SYSTEM_LOG_LEVEL` | `INFO` | SPIKE logging level: `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `SPIKE_TRUST_ROOT` | `poc.local` | Base trust root |
| `SPIKE_TRUST_ROOT_NEXUS` | `poc.local` | Trust root for Nexus validation (required for `IsNexus()` check) |
| `SPIKE_TRUST_ROOT_PILOT` | `poc.local` | Trust root for Pilot CLI validation |
| `SPIKE_TRUST_ROOT_BOOTSTRAP` | `poc.local` | Trust root for Bootstrap validation |
| `SPIKE_TRUST_ROOT_KEEPER` | `poc.local` | Trust root for Keeper validation |
| `SPIKE_TRUST_ROOT_LITE_WORKLOAD` | `poc.local` | Trust root for lite workload validation |
| `SPIFFE_ENDPOINT_SOCKET` | `unix:///tmp/spire-agent/public/api.sock` | SPIRE Workload API socket URI |

### SPIKE Keeper

| Variable | Value | Description |
|----------|-------|-------------|
| `SPIKE_KEEPER_TLS_PORT` | `:8443` | Keeper TLS listen port |
| `HEALTHCHECK_ADDR` | `localhost:8443` | Address for health check probe |
| All `SPIKE_TRUST_ROOT_*` vars | `poc.local` | Same trust roots as Nexus |

### SPIKE Bootstrap

| Variable | Value | Description |
|----------|-------|-------------|
| `SPIKE_NEXUS_API_URL` | `https://spike-nexus:8443` | Nexus URL for post-bootstrap verification |
| `SPIKE_NEXUS_KEEPER_PEERS` | `https://spike-keeper-1:8443` (local demo) / `https://spike-keeper-1:8443,https://spike-keeper-2:8443,https://spike-keeper-3:8443` (production-intent compose) | Keeper URL(s) to send shards to |
| `SPIKE_NEXUS_SHAMIR_THRESHOLD` | `1` (local demo) / `2` (production-intent compose, EKS release bundle) | Bootstrap must match the active Nexus recovery profile |
| `SPIKE_NEXUS_SHAMIR_SHARES` | `1` (local demo) / `3` (production-intent compose, EKS release bundle) | Bootstrap must match the active Nexus recovery profile |

Release-facing compose (`docker-compose.prod-intent.yml`) and the standalone
SPIKE EKS bundle (`deploy/terraform/spike/`) now require multi-share keeper recovery
(`2-of-3` in repo defaults). Keep the `1-of-1` values only for isolated local
demo/bootstrap flows from `docker-compose.yml` and
`deploy/terraform/overlays/local/spike-bootstrap-job.yaml`.

### SPIKE Secret Seeder

| Variable | Value | Description |
|----------|-------|-------------|
| `SPIKE_NEXUS_API_URL` | `https://spike-nexus:8443` | Nexus URL for secret operations |
| `SPIKE_TRUST_ROOT` | `poc.local` | Trust root for mTLS |
| `SPIKE_TRUST_ROOT_NEXUS` | `poc.local` | Nexus trust root |
| `SPIKE_TRUST_ROOT_PILOT` | `poc.local` | Pilot trust root (seeder uses Pilot CLI) |

---

## 4. Phoenix / OpenTelemetry / OpenSearch Variables

The observability stack runs in a separate compose file (`docker-compose.phoenix.yml`).

### Phoenix

| Variable | Value | Description |
|----------|-------|-------------|
| `PHOENIX_PORT` | `6006` | Phoenix UI port |
| `PHOENIX_HOST` | `0.0.0.0` | Phoenix listen address |
| `PHOENIX_GRPC_PORT` | `4317` | Phoenix gRPC (OTLP) receiver port |
| `PHOENIX_WORKING_DIR` | `/data` | Data directory for trace persistence |

**Phoenix UI**: `http://localhost:6006`

### OTel Collector

The OTel Collector is configured via YAML files (see [config/otel-collector-phoenix.yaml](#configotel-collector-phoenixyaml)),
not environment variables. Key ports:

| Port | Protocol | Description |
|------|----------|-------------|
| `4317` | gRPC | OTLP gRPC receiver -- gateway sends traces here |
| `4318` | HTTP | OTLP HTTP receiver |
| `13133` | HTTP | Health check endpoint |

### OpenSearch Profile (Optional)

OpenSearch is intentionally optional and complements Phoenix traces with indexed
audit evidence search and dashboards.

Compose files:

- `docker-compose.opensearch.yml` (OpenSearch, Dashboards, Fluent Bit forwarder)
- `docker-compose.opensearch-bridge.yml` (gateway audit sink override)

Commands:

```bash
make opensearch-up
make opensearch-seed
make opensearch-validate
```

Profile endpoints:

- OpenSearch API: `http://localhost:9200`
- OpenSearch Dashboards: `http://localhost:5601`

Profile-specific audit sink override:

| Variable | Profile Value | Description |
|----------|---------------|-------------|
| `AUDIT_LOG_PATH` | `/var/log/gateway/audit.jsonl` | Set by `docker-compose.opensearch-bridge.yml` so Fluent Bit can ingest gateway audit JSONL |

### `precinct` Compliance Export from OpenSearch

`precinct` supports OpenSearch-backed evidence collection for compliance workflows:

```bash
export PRECINCT_OPENSEARCH_PASSWORD='<secret>'
go run ./cli/precinct compliance collect \
  --framework soc2 \
  --audit-source opensearch \
  --opensearch-url https://opensearch.observability.svc.cluster.local:9200 \
  --opensearch-index 'precinct-audit-*' \
  --opensearch-ca-cert /certs/ca.crt \
  --opensearch-client-cert /certs/client.crt \
  --opensearch-client-key /certs/client.key
```

Security requirements enforced by CLI when `--audit-source opensearch`:

- Password must come from env var (`--opensearch-password-env`, default `PRECINCT_OPENSEARCH_PASSWORD`)
- `--opensearch-ca-cert` is required
- `--opensearch-client-cert` and `--opensearch-client-key` are required
- OpenSearch URL must be `https://`

---

## 5. MCP-UI Environment Variables

These environment variables override values from `config/ui.yaml`. They are
applied after the YAML file is loaded. Source: `internal/gateway/ui_config.go`
function `ApplyEnvOverrides()`.

| Variable | Default (from YAML) | Description |
|----------|---------------------|-------------|
| `UI_ENABLED` | `false` | Global kill switch for MCP-UI. When `false`, all `_meta.ui` is stripped |
| `UI_DEFAULT_MODE` | `deny` | Default mode for servers without grants: `deny`, `audit-only`, or `allow` |
| `UI_MAX_RESOURCE_SIZE_BYTES` | `2097152` (2 MB) | Maximum size of a UI resource in bytes |
| `UI_RESOURCE_FETCH_TIMEOUT_SECONDS` | `10` | Timeout for fetching UI resources |
| `UI_SCAN_ENABLED` | `true` | Enable content scanning for dangerous patterns |
| `UI_HASH_VERIFICATION_ENABLED` | `true` | Enable hash verification for UI resources (rug-pull detection) |

---

## 6. Configuration Files

All configuration files live in the `config/` directory. They are mounted
read-only into the gateway container at `/config/`.

### config/tool-registry.yaml

**Purpose**: Defines MCP tools registered with the gateway. Each tool entry
includes a SHA-256 hash for poisoning detection.

**Format**:
```yaml
tools:
  - name: "tavily_search"
    description: "Search the web using Tavily API"
    hash: "76c6b3d8..."  # SHA-256
    input_schema:
      type: "object"
      required: ["query"]
      properties:
        query:
          type: "string"
    allowed_destinations:
      - "api.tavily.com"
    risk_level: "medium"        # low, medium, critical
    requires_step_up: false     # true = step-up auth required
    required_scope: "tools.tavily.search"  # SPIKE token scope

ui_resources:
  - server: "dashboard-server"
    resource_uri: "ui://dashboard/analytics.html"
    content_hash: "944c21cc..."  # SHA-256 of raw content
    version: "1.0.0"
    declared_csp: { ... }
    declared_perms: { ... }
```

**Hash computation**: `SHA-256(description + canonical_json(input_schema))`
computed by `scripts/compute_tool_hashes.go`.

**Key fields per tool**:
- `name` -- tool identifier, must match what the MCP server declares
- `hash` -- SHA-256 of description + input schema; mismatches are flagged as tool poisoning
- `risk_level` -- `low`, `medium`, or `critical`; drives risk scoring
- `requires_step_up` -- whether step-up authentication is required before execution
- `allowed_destinations` -- domain patterns for egress control
- `allowed_paths` -- filesystem path patterns (uses `${ALLOWED_BASE_PATH}` substitution)
- `required_scope` -- SPIKE token scope needed for invocation

### config/spiffe-ids.yaml

**Purpose**: Documents the SPIFFE ID schema for all workloads. Used as a
reference; the actual SPIFFE entries are registered by `scripts/register-spire-entries.sh`.

**SPIFFE ID pattern**: `spiffe://<trust-domain>/<agent-class>/<agent-purpose>/<environment>`

**Registered workloads**:

| SPIFFE ID | Workload | Docker Selector |
|-----------|----------|-----------------|
| `spiffe://poc.local/gateways/precinct-gateway/dev` | Gateway | `docker:label:spiffe-id:precinct-gateway` |
| `spiffe://poc.local/agents/mcp-client/dspy-researcher/dev` | DSPy Agent | `docker:label:spiffe-id:dspy-researcher` |
| `spiffe://poc.local/agents/mcp-client/pydantic-researcher/dev` | PydanticAI Agent | `docker:label:spiffe-id:pydantic-researcher` |
| `spiffe://poc.local/spike/nexus` | SPIKE Nexus | `docker:label:spiffe-id:spike-nexus` |
| `spiffe://poc.local/spike/keeper/1` | SPIKE Keeper 1 | `docker:label:spiffe-id:spike-keeper-1` |
| `spiffe://poc.local/spike/bootstrap` | SPIKE Bootstrap | `docker:label:spiffe-id:spike-bootstrap` |
| `spiffe://poc.local/spike/pilot/role/superuser/seeder` | Secret Seeder | `docker:label:spiffe-id:spike-seeder` |
| `spiffe://poc.local/keydb` | KeyDB | `docker:label:spiffe-id:keydb` |

### config/destinations.yaml

**Purpose**: Allowlist of trusted destinations for step-up gating. Tool calls
with risk score 4-6 to destinations NOT on this list are blocked with HTTP 403.

**Format**:
```yaml
allowed_destinations:
  - "localhost"
  - "127.0.0.1"
  - "host.docker.internal"
  - "api.tavily.com"
  - "*.tavily.com"       # Wildcard prefix matching
  - "api.groq.com"
  - "*.groq.com"
  - "api.github.com"
  - "*.github.com"
```

Wildcard patterns use prefix matching: `*.tavily.com` matches `api.tavily.com`,
`search.tavily.com`, etc.

### config/risk_thresholds.yaml

**Purpose**: Configures the 4-dimensional risk scoring rubric thresholds,
guard model thresholds, and DLP policy per content category.

**Format**:
```yaml
thresholds:
  fast_path_max: 3     # 0-3: no friction (fast path)
  step_up_max: 6       # 4-6: step-up gating (destination check + guard model)
  approval_max: 9      # 7-9: human approval required (HTTP 403 stub)
  # 10-12: deny by default

guard:
  injection_threshold: 0.30    # Block if InjectionProbability > this
  jailbreak_threshold: 0.30    # Block if JailbreakProbability > this

unknown_tool_defaults:
  impact: 2
  reversibility: 2
  exposure: 2
  novelty: 3            # Unknown tools get max novelty

dlp:
  credentials: block    # ALWAYS block (security invariant)
  injection: flag       # block or flag (overridable via DLP_INJECTION_POLICY env var)
  pii: flag             # block or flag
```

Risk scoring uses 4 dimensions (0-3 each) for a total range of 0-12.

### config/ui.yaml

**Purpose**: MCP-UI (Apps Extension) security configuration. Defines global
constraints that capability grants cannot override.

See the [MCP-UI Environment Variables](#5-mcp-ui-environment-variables) section
for environment variable overrides.

**Format**:
```yaml
ui:
  enabled: false              # Global kill switch
  default_mode: "deny"        # deny | audit-only | allow
  max_resource_size_bytes: 2097152
  resource_fetch_timeout_seconds: 10
  resource_cache_ttl_seconds: 300
  scan_enabled: true
  block_on_dangerous_patterns: true
  hash_verification_enabled: true

  csp_hard_constraints:
    frame_domains_allowed: false
    base_uri_domains_allowed: false
    max_connect_domains: 5
    max_resource_domains: 10

  permissions_hard_constraints:
    camera_allowed: false
    microphone_allowed: false
    geolocation_allowed: false
    clipboard_write_allowed: false

  app_tool_calls:
    separate_rate_limit: true
    requests_per_minute: 20
    burst: 5
    force_step_up_for_high_risk: true

  strip_ui_for_incompatible_hosts: true
```

**Configuration hierarchy**: Hard constraints are set by the security team and
cannot be overridden by per-server capability grants. A grant cannot enable
camera access when `permissions_hard_constraints.camera_allowed=false`.

### config/otel-collector.yaml / config/otel-collector-phoenix.yaml

**Purpose**: OpenTelemetry Collector pipeline configuration. The Phoenix variant
(`config/otel-collector-phoenix.yaml`) includes a 6-line header comment but is
functionally identical to the base config. It is mounted by `docker-compose.phoenix.yml`.

**Pipeline structure**:
```
Receivers (OTLP gRPC :4317, HTTP :4318)
  -> Processors (batch: 1s/1024, resource attributes)
  -> Exporters (otlp/phoenix -> phoenix:4317, debug)
```

**Pipelines**: `traces` exports to Phoenix + debug. `metrics` and `logs`
export to `debug` only because Phoenix is used as the trace backend.

### config/spire/server.conf

**Purpose**: SPIRE Server HCL configuration.

**Key settings**:
- Trust domain: `poc.local`
- DataStore: SQLite3
- NodeAttestor: `join_token`
- KeyManager: disk-based

### config/spire/agent.conf

**Purpose**: SPIRE Agent HCL configuration.

**Key settings**:
- Server: `spire-server:8081`
- NodeAttestor: `join_token`
- WorkloadAttestor: `docker` (with `use_new_container_locator=true`) + `unix`
- `insecure_bootstrap = true` (development only)

---

## 7. OPA Policy Structure

The OPA policy engine runs embedded in the gateway. Policy files and data are
loaded from `OPA_POLICY_DIR` (default: `/config/opa`).

### Policy Files

| File | Package | Purpose |
|------|---------|---------|
| `mcp_policy.rego` | `mcp` | Main authorization policy: SPIFFE ID matching, tool authorization, path/destination restrictions, step-up gating, session risk |
| `context_policy.rego` | `mcp.context` | Context injection gating for external content |
| `exfiltration.rego` | `mcp.exfiltration` | Cross-tool exfiltration pattern detection |
| `ui_policy.rego` | `mcp.ui.policy` | UI resource and app-driven tool call authorization |
| `ui_csp_policy.rego` | `mcp.ui.csp` | CSP and permissions mediation for MCP-UI |
| `mcp_policy_test.rego` | -- | Tests for main policy (run with `opa test config/opa/ -v`) |
| `ui_policy_test.rego` | -- | Tests for UI policy |
| `ui_csp_policy_test.rego` | -- | Tests for CSP policy |

### Data Files

| File | Purpose |
|------|---------|
| `tool_grants.yaml` | Maps SPIFFE ID patterns to authorized tools |
| `tool_registry.yaml` | Tool definitions with risk levels for OPA |
| `ui_capability_grants.yaml` | Per-server, per-tenant UI capability grants |

### Authorization Model (`mcp_policy.rego`)

The main authorization decision (`allow`) evaluates five conditions in sequence.
All must pass for the request to be allowed:

1. **SPIFFE ID matching** -- `spiffe_matches(input.spiffe_id, grant.spiffe_pattern)`
   - Exact match or wildcard match (e.g., `spiffe://poc.local/agents/mcp-client/*/dev`)

2. **Tool authorization** -- `tool_authorized(input.tool, grant.allowed_tools)`
   - Tool must be in the grant's `allowed_tools` list, or grant uses `"*"` wildcard

3. **Path restrictions** -- `path_allowed(input.tool, input.params)`
   - `read` and `grep` tools: file path must start with `ALLOWED_BASE_PATH`
   - `bash`: no path restriction (handled by step-up)
   - Other tools: pass through

4. **Destination restrictions** -- `destination_allowed(input.tool, input.params)`
   - `tavily_search`: allowed (trusted destination)
   - `bash`: blocked if command contains `curl`, `wget`, or `http`
   - Other tools: default deny external egress

5. **Step-up gating** -- `step_up_satisfied(input.tool, input.step_up_token)`
   - If `requires_step_up=true` in tool registry, a non-empty step-up token must be present

6. **Session risk** -- `session_risk_acceptable`
   - `input.session.risk_score` must be below 0.7

**Denial reasons** (returned in the `reason` field):
- `default_deny` -- no conditions evaluated
- `no_matching_grant` -- SPIFFE ID has no grant
- `tool_not_authorized` -- tool not in allowed list
- `path_denied` -- file path outside allowed base
- `destination_denied` -- external destination blocked
- `step_up_required` -- step-up token missing
- `session_risk_too_high` -- session risk score >= 0.7

### Tool Grants (`tool_grants.yaml`)

Each grant maps a SPIFFE ID pattern to allowed tools:

```yaml
tool_grants:
  - spiffe_pattern: "spiffe://poc.local/agents/mcp-client/*-researcher/dev"
    description: "Research agents"
    allowed_tools:
      - read
      - grep
      - tavily_search
    max_data_classification: internal
    requires_approval_for:
      - bash
      - file_write
```

**Key fields**:
- `spiffe_pattern` -- SPIFFE ID or wildcard pattern
- `allowed_tools` -- list of tool names, or `["*"]` for all tools
- `max_data_classification` -- `public`, `internal`, `sensitive`, `confidential`
- `requires_approval_for` -- tools that need human approval

### Poisoning Detection (`mcp_policy.rego`)

The policy includes `contains_poisoning_indicators(description)` which detects
7 patterns in tool descriptions:
1. `<IMPORTANT>` tags
2. `<SYSTEM>` tags
3. HTML comments (`<!-- ... -->`)
4. "before using this tool...first" instruction injection
5. "ignore previous/all/prior instructions"
6. "you must always/first/never" commands
7. "send...to" with email/http/webhook/upload

### Running OPA Tests

```bash
opa test config/opa/ -v
```

---

## 8. DLP Policy Configuration

DLP (Data Loss Prevention) scanning runs as middleware step 7 in the gateway
pipeline. It scans request content for three categories of sensitive data using
regex patterns.

### Policy Per Category

| Category | Default | Configurable | Description |
|----------|---------|--------------|-------------|
| `credentials` | `block` | **No** -- security invariant | API keys, passwords, tokens. Always blocks; cannot be changed via env var. Change requires editing `config/risk_thresholds.yaml` |
| `injection` | `flag` | **Yes** -- `DLP_INJECTION_POLICY` env var | Prompt injection patterns. Default: flag (add to safezone_flags, continue). Set to `block` for strict enforcement |
| `pii` | `flag` | No -- YAML only | Personally identifiable information (SSN, email, phone). Change requires editing `config/risk_thresholds.yaml` |

### Behavior

- **`block`** -- returns HTTP 403 immediately, request is denied
- **`flag`** -- adds a flag to `safezone_flags` in the audit log and continues processing

### Configuration Hierarchy

1. `config/risk_thresholds.yaml` defines base policy per category
2. `DLP_INJECTION_POLICY` env var overrides ONLY the `injection` category
3. `credentials=block` is a **security invariant** -- it is intentionally NOT
   overridable via environment variable to prevent accidental weakening

### Design Rationale

Only `injection` has an env var override because:
- **Credentials** (`block`): Credential leakage through tool calls must always be
  blocked. Making this easily toggleable via env var risks accidental degradation of
  a critical security control.
- **PII** (`flag`): PII audit-only policy is the standard approach across compliance
  frameworks. Operators who need to change this should do so deliberately via YAML
  config, not a quick env var toggle.
- **Injection** (`flag`/`block`): Injection policy legitimately varies by deployment
  context -- development environments may prefer `flag` for visibility while
  production may require `block`.

---

## 9. Escalation Thresholds

Escalation detection tracks cumulative destructiveness within an agent session. The
thresholds are currently hardcoded constants in `internal/gateway/middleware/escalation.go`:

| Constant | Value | Description |
|----------|-------|-------------|
| `EscalationWarningThreshold` | `15.0` | Session score at which `escalation_warning` flag is set |
| `EscalationCriticalThreshold` | `25.0` | Session score at which `escalation_critical` flag is set |
| `EscalationEmergencyThreshold` | `40.0` | Session score at which `escalation_emergency` flag is set and request is denied (HTTP 403) |

**Scoring formula:** `contribution = Impact x (4 - Reversibility)`

Each tool action contributes to the cumulative session score. The score is persisted
in KeyDB alongside other session state.

---

## 10. Data Source Registry

The tool registry (`config/tool-registry.yaml`) supports a `data_sources` extension
for external data source integrity verification. Each entry is a `DataSourceDefinition`:

```yaml
data_sources:
  - uri: "https://example.com/dataset.json"
    content_hash: "sha256:abc123..."
    approved_at: "2026-03-01T00:00:00Z"
    approved_by: "spiffe://poc.local/agents/admin/dev"
    max_size_bytes: 10485760
    mutable_policy: "block_on_change"  # block_on_change | flag_on_change | allow
    refresh_ttl: "1h"
```

| Field | Type | Description |
|-------|------|-------------|
| `uri` | string | External data source URI |
| `content_hash` | string | Expected SHA-256 hash (`sha256:<hex>`) |
| `approved_at` | timestamp | When the data source was last approved |
| `approved_by` | string | SPIFFE ID of the approver |
| `max_size_bytes` | integer | Maximum allowed data source size |
| `mutable_policy` | string | `"block_on_change"`, `"flag_on_change"`, or `"allow"` |
| `refresh_ttl` | duration | How often to re-verify the data source hash |

Data source definitions are hot-reloaded via the existing `fsnotify` watcher alongside
tool definitions.

---

## 11. Port Adapter Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCORD_PUBLIC_KEY` | _(empty)_ | Ed25519 public key (hex-encoded) for Discord webhook signature verification. Required when the Discord adapter is active |

---

## 12. Principal Mapping Configuration

The `principal_mapping` YAML config section maps SPIFFE path prefixes to principal levels.
This is loaded from `config/principal_mapping.yaml` or embedded in the gateway's main
config file.

**Default mapping** (derived from SPIFFE ID path segments):

```yaml
principal_mapping:
  system: 0      # /system/ prefix -> Level 0
  owner: 1       # /owner/ prefix -> Level 1
  delegated: 2   # /delegated/ prefix -> Level 2
  agents: 3      # /agents/ prefix -> Level 3
  external: 4    # /external/ prefix -> Level 4
  anonymous: 5   # (no match) -> Level 5
```

Each key is a SPIFFE path segment prefix. When the gateway resolves a principal from a
SPIFFE ID (e.g., `spiffe://poc.local/agents/example/dev`), it matches the first path
segment (`agents`) against this mapping to determine the principal level (3).

Custom deployments can override this mapping to add organization-specific path prefixes
or adjust the hierarchy. For example, adding `contractors: 3` would map
`/contractors/` paths to Level 3 (same as agents).

---

## 13. Reversibility Overrides Configuration

The `reversibility_overrides` YAML config section provides per-tool reversibility score
overrides. This is loaded from `config/reversibility_overrides.yaml` or embedded in the
gateway's main config file.

**Format:**

```yaml
reversibility_overrides:
  bash: 3          # Always irreversible regardless of action parameter
  s3_delete: 3     # S3 delete is always irreversible
  tavily_search: 0 # Search is always reversible
```

Each key is a tool name from `config/tool-registry.yaml`. The integer value (0-3) overrides
the pattern-based reversibility classification for all invocations of that tool:

| Score | Category |
|-------|----------|
| 0 | reversible |
| 1 | costly_reversible |
| 2 | partially_reversible |
| 3 | irreversible |

When a tool has a reversibility override, the gateway skips pattern-based classification
(which examines action parameters for trigger patterns like `delete`, `rm`, `drop`) and
uses the override score directly. This is useful for tools where the tool name itself
implies a fixed reversibility level regardless of arguments.

---

## 14. SPIFFE ID Schema

All workload identities follow the pattern defined in the Reference Architecture
Section 4.5.

### Schema

```
spiffe://<trust-domain>/<agent-class>/<agent-purpose>/<environment>
```

| Component | Description | Examples |
|-----------|-------------|---------|
| `trust-domain` | Organization identifier | `poc.local` |
| `agent-class` | Workload category | `gateways`, `agents/mcp-client`, `tools`, `spike`, `infrastructure` |
| `agent-purpose` | Functional identifier | `precinct-gateway`, `dspy-researcher` |
| `environment` | Deployment environment | `dev`, `staging`, `prod` |

### Wildcard Patterns for OPA Policies

| Pattern | Matches |
|---------|---------|
| `spiffe://poc.local/gateways/*/dev` | All gateways in dev |
| `spiffe://poc.local/agents/mcp-client/*/dev` | All MCP client agents |
| `spiffe://poc.local/agents/mcp-client/*-researcher/dev` | All researcher agents |
| `spiffe://poc.local/tools/*/dev` | All tool servers |

### Docker Compose Attestation

SPIRE identifies workloads using Docker container labels. Each service in
`docker-compose.yml` must have a `spiffe-id` label matching the SPIRE entry
registration in `scripts/register-spire-entries.sh`.

Example:
```yaml
# docker-compose.yml
precinct-gateway:
  labels:
    - "spiffe-id=precinct-gateway"    # Matches SPIRE selector
    - "component=gateway"

# register-spire-entries.sh
reg "spiffe://poc.local/gateways/precinct-gateway/dev" \
    -selector docker:label:spiffe-id:precinct-gateway \
    -selector docker:label:component:gateway
```

### K8s Attestation (Local Overlay)

In the Kubernetes local overlay (`deploy/terraform/overlays/local/`), the trust domain
changes to `precinct.poc` and SPIRE uses `join_token` attestation
instead of Docker labels.
