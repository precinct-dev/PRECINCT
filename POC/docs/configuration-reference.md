# Configuration Reference

This document is the single reference for all environment variables, configuration files,
and policy customization options for the MCP Security Gateway and its supporting infrastructure.

All defaults listed here are verified against source code in `internal/gateway/config.go`
and runtime values in `docker-compose.yml`.

---

## Table of Contents

1. [Gateway Environment Variables](#1-gateway-environment-variables)
2. [SPIRE Environment Variables](#2-spire-environment-variables)
3. [SPIKE Environment Variables](#3-spike-environment-variables)
4. [Phoenix / OpenTelemetry Environment Variables](#4-phoenix--opentelemetry-environment-variables)
5. [MCP-UI Environment Variables](#5-mcp-ui-environment-variables)
6. [Configuration Files](#6-configuration-files)
7. [OPA Policy Structure](#7-opa-policy-structure)
8. [DLP Policy Configuration](#8-dlp-policy-configuration)
9. [SPIFFE ID Schema](#9-spiffe-id-schema)

---

## 1. Gateway Environment Variables

These variables configure the `mcp-security-gateway` service. Source: `internal/gateway/config.go`
function `ConfigFromEnv()`.

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9090` | HTTP listen port for the gateway |
| `UPSTREAM_URL` | `http://host.docker.internal:8081/mcp` | Backend MCP server URL. Docker Compose overrides to `http://mock-mcp-server:8082` |
| `MAX_REQUEST_SIZE_BYTES` | `10485760` (10 MB) | Maximum request body size in bytes |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `AUDIT_LOG_PATH` | `/var/log/gateway/audit.jsonl` | Path to the JSONL audit log file |
| `SPIFFE_MODE` | `dev` | SPIFFE operating mode: `dev` (HTTP, no mTLS) or `prod` (HTTPS with SPIRE mTLS) |
| `SPIFFE_TRUST_DOMAIN` | `poc.local` | SPIFFE trust domain for workload identity |
| `SPIFFE_LISTEN_PORT` | `9443` | HTTPS listen port when `SPIFFE_MODE=prod` |
| `SPIFFE_ENDPOINT_SOCKET` | _(none)_ | SPIRE Workload API socket URI (e.g., `unix:///tmp/spire-agent/public/api.sock`). This is the only SPIRE socket variable the gateway reads; `SPIRE_AGENT_SOCKET` (set in docker-compose.yml) is not consumed by gateway code |
| `MCP_TRANSPORT_MODE` | `mcp` | Transport mode: `mcp` (MCP Streamable HTTP) or `proxy` (reverse proxy, backward compatible) |
| `ALLOWED_BASE_PATH` | Current working directory | Base directory for OPA path-based access control (read/grep tools). All file access is restricted to paths under this directory |

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
| `TOOL_REGISTRY_PUBLIC_KEY` | _(empty)_ | Path to PEM public key for tool registry attestation. Empty = dev mode (no signature verification) |
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
| `OTEL_SERVICE_NAME` | `mcp-security-gateway` | Service name in emitted traces |

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
| `SPIKE_NEXUS_KEEPER_PEERS` | `https://spike-keeper-1:8443` | Comma-separated list of Keeper URLs for Shamir recovery |
| `SPIKE_NEXUS_SHAMIR_THRESHOLD` | `1` | Minimum Keeper shards needed for root key reconstruction |
| `SPIKE_NEXUS_SHAMIR_SHARES` | `1` | Total Shamir shards (development uses 1; production should use 3+) |
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
| `SPIKE_NEXUS_KEEPER_PEERS` | `https://spike-keeper-1:8443` | Keeper URL(s) to send shards to |
| `SPIKE_NEXUS_SHAMIR_THRESHOLD` | `1` | Must match Nexus config |
| `SPIKE_NEXUS_SHAMIR_SHARES` | `1` | Must match Nexus config |

### SPIKE Secret Seeder

| Variable | Value | Description |
|----------|-------|-------------|
| `SPIKE_NEXUS_API_URL` | `https://spike-nexus:8443` | Nexus URL for secret operations |
| `SPIKE_TRUST_ROOT` | `poc.local` | Trust root for mTLS |
| `SPIKE_TRUST_ROOT_NEXUS` | `poc.local` | Nexus trust root |
| `SPIKE_TRUST_ROOT_PILOT` | `poc.local` | Pilot trust root (seeder uses Pilot CLI) |

---

## 4. Phoenix / OpenTelemetry Environment Variables

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
| `spiffe://poc.local/gateways/mcp-security-gateway/dev` | Gateway | `docker:label:spiffe-id:mcp-security-gateway` |
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
  -> Exporters (otlp_grpc/phoenix -> phoenix:4317, debug)
```

**Pipelines**: `traces`, `metrics`, `logs` -- all follow the same
receiver -> processor -> exporter path.

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

## 9. SPIFFE ID Schema

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
| `agent-purpose` | Functional identifier | `mcp-security-gateway`, `dspy-researcher` |
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
mcp-security-gateway:
  labels:
    - "spiffe-id=mcp-security-gateway"    # Matches SPIRE selector
    - "component=gateway"

# register-spire-entries.sh
reg "spiffe://poc.local/gateways/mcp-security-gateway/dev" \
    -selector docker:label:spiffe-id:mcp-security-gateway \
    -selector docker:label:component:gateway
```

### K8s Attestation (Local Overlay)

In the Kubernetes local overlay (`infra/eks/overlays/local/`), the trust domain
changes to `agentic-ref-arch.poc` and SPIRE uses `join_token` attestation
instead of Docker labels.
