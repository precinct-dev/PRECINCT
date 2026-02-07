# ARCHITECTURE.md -- Phase 2: Agentic AI Security Reference Architecture POC

**Version:** 1.0
**Date:** 2026-02-06
**Author:** Architect (D&F Phase)
**Status:** Draft for BLT Review

---

## 1. System Overview

Phase 2 hardens the Docker Compose POC delivered in Phase 1 (70 stories, 13-middleware chain, 594 tests) and extends it to local Kubernetes, real secrets management, cross-request session persistence, mTLS, full observability, and one-button compliance reporting.

The system remains a **reverse-proxy gateway** written in Go that interposes between AI agents and MCP tool servers. Phase 2 adds five infrastructure services (SPIKE Nexus, KeyDB, OpenBAO, OTel Collector, SPIRE with mTLS enforcement) and two offline toolchains (compliance report generator, CLI setup wizard).

### 1.1 Architecture Diagram

```
                                    +-----------+
                                    |  Agent    |
                                    | (any SDK) |
                                    +-----+-----+
                                          |
                                    MCP JSON-RPC / HTTPS (mTLS)
                                          |
                                          v
+-------------------------------------------------------------------------------------+
|                           MCP SECURITY GATEWAY (Go)                                  |
|                                                                                      |
|  +------+  +------+  +------+  +------+  +------+  +------+  +------+               |
|  | 1.Sz | >| 2.BC | >| 3.SP | >| 4.AU | >| 5.TR | >| 6.OP | >| 7.DL |              |
|  | Limit|  | Body |  | Auth |  | Audit|  | Reg  |  | Auth |  | Scan |              |
|  +------+  +------+  +------+  +------+  +------+  +------+  +------+               |
|                                                                                      |
|  +------+  +------+  +------+  +------+  +------+  +------+                         |
|  | 8.SC | >| 9.SU | >|10.DS | >|11.RL | >|12.CB | >|13.TS |-----> Proxy            |
|  | Sess |  | Gate |  | Deep |  | Rate |  | Circ |  | Token|   (ResponseFirewall)    |
|  +------+  +------+  +------+  +------+  +------+  +------+                         |
|                                                                                      |
+---+----------+----------+-----------+-----------+------------------------------------+
    |          |          |           |           |
    v          v          v           v           v
+------+  +-------+  +--------+  +------+  +----------+
| SPIRE|  | KeyDB |  | SPIKE  |  | OTel |  | MCP Tool |
| Srvr |  |(sess +|  | Nexus  |  | Coll |  | Server   |
|+Agent|  | rate) |  |        |  |->Phx |  |          |
+------+  +-------+  +--------+  +------+  +----------+
                          |
                          v
                     +---------+
                     | OpenBAO | (K8s Tier 2 only)
                     +---------+
```

### 1.2 Technology Stack

| Component | Technology | Version | License | Rationale |
|-----------|-----------|---------|---------|-----------|
| Gateway | Go | 1.23+ | BSD-3 | Performance, static binary, strong concurrency |
| Policy engine | OPA (embedded) | 0.62+ | Apache-2.0 | Eliminates sidecar failure mode |
| Identity | SPIFFE/SPIRE | 1.10.0 | Apache-2.0 | CNCF-standard workload identity |
| Secrets | SPIKE Nexus | 0.8.0 | Apache-2.0 | SPIFFE-native, late-binding tokens |
| Secrets backend (K8s) | OpenBAO | 2.4+ | MPL-2.0 | Open-source Vault fork, enterprise-safe license |
| Session store | KeyDB | eqalpha/keydb:6.3.4 | BSD-3 | Redis-compatible, truly open license |
| Observability | OTel SDK (Go) | 1.28+ | Apache-2.0 | Vendor-neutral, per-middleware spans |
| Trace backend | Phoenix | latest | Apache-2.0 | OTel-native, zero-config |
| OTel pipeline | OTel Collector Contrib | latest | Apache-2.0 | Standard pipeline |
| Container signing | cosign | 2.2+ | Apache-2.0 | Keyless OIDC signing (K8s only) |
| Admission | sigstore/policy-controller | latest | Apache-2.0 | Signature verification webhook (K8s only) |
| IaC | OpenTofu | 1.6+ | MPL-2.0 | Terraform fork, enterprise-safe license |
| Compliance reports | Python | 3.11+ | PSF | openpyxl (XLSX), csv (stdlib), fpdf2 (PDF) |

---

## 2. Architectural Decisions

Each decision records what was decided, why, what alternatives were rejected, and what trade-offs were accepted.

### ADR-001: SPIKE Nexus Integration -- Three-Tier Backend Progression

**Decision:** SPIKE Nexus integrates with the gateway's token substitution middleware (step 13) through a `SecretRedeemer` interface. Three backend tiers are supported:

| Tier | Deployment | Backend | Secret Storage |
|------|-----------|---------|---------------|
| 1 | Docker Compose | SPIKE Nexus with local encrypted storage | In-memory root key, AES-256-GCM encrypted SQLite |
| 2 | Local K8s / EKS | SPIKE Nexus backed by OpenBAO | OpenBAO Secrets Engine (KV v2) |
| 3 | Cloud (future) | Native KMS | AWS KMS / GCP KMS / Azure Key Vault |

**Image:** `ghcr.io/spiffe/spike-nexus:0.8.0` (built from `github.com/spiffe/spike` -- the Dockerfiles directory contains `nexus.Dockerfile`). The EKS manifests previously referenced `vsecm/spike-nexus:0.3.0`; this is updated to the current SPIFFE-org image at 0.8.0.

**Service architecture:**

```
Agent                     Gateway                    SPIKE Nexus
  |                         |                           |
  | 1. spike secret put     |                           |
  |    (via SPIKE Pilot)    |                           |
  |-------- direct -------->|                           |
  |                         |                           |
  | 2. Tool call with       |                           |
  |    $SPIKE{ref:abc123}   |                           |
  |------------------------>|                           |
  |                         | 3. ValidateToken(ref)     |
  |                         |    mTLS (SVID)            |
  |                         |-------------------------->|
  |                         |                           |
  |                         | 4. RedeemSecret(ref)      |
  |                         |    mTLS (SVID)            |
  |                         |<--------------------------|
  |                         |                           |
  |                         | 5. Substitute in outbound |
  |                         |    request body/headers   |
  |                         |                           |
  | 6. Response             |                           |
  |    (agent never saw     |                           |
  |     raw secret)         |                           |
  |<------------------------|                           |
```

**Key initialization (Docker Compose, Tier 1):**
1. SPIKE Nexus starts with SPIRE agent socket mounted (same as other services).
2. SPIKE Bootstrap runs as a one-shot init container (like `spire-token-generator`) to generate and deliver the root key.
3. SPIKE Pilot (CLI) is used by the setup script to seed initial secrets: `spike secret put external-apis/groq-key value=$GROQ_API_KEY`.
4. The gateway's `SecretRedeemer` implementation makes mTLS calls to `https://spike-nexus:8443/v1/store/secret/get` to redeem tokens.

**Gateway code changes:**
- Replace `POCSecretRedeemer` in `internal/gateway/middleware/hooks.go` with a `SPIKENexusRedeemer` that uses `spike-sdk-go` or raw HTTP+mTLS.
- Add `SPIKE_NEXUS_URL` to `Config` (default: `https://spike-nexus:8443`).
- The `TokenSubstitution` middleware signature changes to accept a `SecretRedeemer` parameter instead of creating `NewPOCSecretRedeemer()` internally.

**Alternatives rejected:**
- HashiCorp Vault: BSL licensing is incompatible with enterprise-safe reference architecture (BUSINESS.md Section 5.1).
- Direct env var injection: Agents would see raw secrets in memory, violating the core value proposition.
- SPIKE Pilot as sidecar for each service: Unnecessary complexity; gateway is the single substitution point.

**Trade-offs accepted:**
- SPIKE is at "Development" maturity (not production-ready per SPIFFE lifecycle). Acceptable for a reference architecture POC. Documented as a known limitation.
- Docker Compose Tier 1 uses in-memory root key (lost on restart). Acceptable for POC; Keepers (Tier 4) solve this for production.

---

### ADR-002: KeyDB Data Model for Session Persistence and Rate Limiting

**Decision:** KeyDB replaces the in-memory `sync.Map` in `SessionContext` and the in-memory token bucket in `RateLimiter`. A single KeyDB instance serves both functions with distinct key namespaces.

**Data model:**

```
Session Context Keys:
  session:{spiffe_id}:{session_id}         -> JSON-serialized AgentSession
  session:{spiffe_id}:{session_id}:actions -> LIST of JSON-serialized ToolAction records
  TTL: 3600s (1 hour, configurable via SESSION_TTL)

Rate Limiting Keys:
  ratelimit:{spiffe_id}:tokens     -> STRING (current token count, float64)
  ratelimit:{spiffe_id}:last_fill  -> STRING (Unix timestamp of last refill)
  TTL: 120s (2x the refill window, auto-expires stale entries)

GDPR/CCPA Keys:
  gdpr:sessions:{spiffe_id}        -> SET of session_id values (for right-to-deletion)
  TTL: matches SESSION_TTL
```

**Data structures rationale:**
- Sessions use JSON STRING + LIST (not HASH) because `AgentSession` is read-modify-write as a unit, and actions are append-only. LIST provides O(1) append and O(N) range reads for exfiltration pattern detection (lookback of 5 actions).
- Rate limiting uses two STRING keys instead of a Lua script because KeyDB's multi-threaded model makes Lua scripts less necessary, and the token bucket algorithm needs only atomic GET+SET with optimistic concurrency.

**GDPR/CCPA compliance (BUSINESS.md Section 5.4):**
- **Retention policy:** Session data expires automatically via TTL (default 1 hour). No session data persists beyond TTL without explicit renewal.
- **Right-to-deletion:** `DELETE gdpr:sessions:{spiffe_id}` followed by `DEL session:{spiffe_id}:*` (pattern delete). Exposed as `make gdpr-delete SPIFFE_ID=...`.
- **Data processing records:** The compliance report generator documents that KeyDB stores session_id, spiffe_id, tool actions (tool name, timestamp, classification), and risk scores. No PII from request payloads is stored in session context. The session middleware explicitly does NOT store request/response bodies.
- **Encryption at rest:** KeyDB does not natively encrypt at rest. For Docker Compose, data is ephemeral (Docker volume, lost on `docker compose down -v`). For K8s, use encrypted PVCs via StorageClass with encryption.
- **Encryption in transit:** KeyDB TLS is enabled via `--tls-port 6380 --tls-cert-file --tls-key-file` with SPIRE-issued certificates in prod mode.

**Connection pooling:**
- Go Redis client (`github.com/redis/go-redis/v9`) with connection pool: min 5, max 20 connections. Configurable via `KEYDB_POOL_MIN` and `KEYDB_POOL_MAX`.

**Docker Compose integration:**
```yaml
keydb:
  image: eqalpha/keydb:6.3.4
  container_name: keydb
  hostname: keydb
  ports:
    - "6379:6379"
  volumes:
    - keydb-data:/data
  networks:
    - agentic-net
  healthcheck:
    test: ["CMD", "keydb-cli", "ping"]
    interval: 10s
    timeout: 3s
    retries: 5
```

**Gateway code changes:**
- Add `KeyDBURL` to `Config` (default: `redis://keydb:6379`, env: `KEYDB_URL`).
- `SessionContext` gains a `store` interface with `InMemoryStore` (fallback) and `KeyDBStore` implementations.
- `RateLimiter` gains a `store` interface with `InMemoryStore` (fallback) and `KeyDBStore` implementations.
- When `KEYDB_URL` is empty, both fall back to in-memory (Phase 1 behavior preserved).

**Alternatives rejected:**
- Redis: SSPL licensing concern (BUSINESS.md Section 5.1).
- DragonflyDB: BSD-3 but less mature wire compatibility with Redis clients.
- Embedded bbolt/BadgerDB: No distributed rate limiting possible; session context would be gateway-instance-local.

---

### ADR-003: mTLS Enforcement via SPIRE-Native SVIDs

**Decision:** Use SPIRE-native X.509 SVIDs for mTLS between all services. No cert-manager. SPIRE is already the identity control plane; introducing cert-manager would add a second certificate authority and a second trust root, creating a confused-deputy risk.

**How mTLS works per deployment target:**

| Aspect | Docker Compose | K8s (local + EKS) |
|--------|---------------|-------------------|
| SVID source | SPIRE Agent Workload API socket | SPIRE Agent DaemonSet Workload API |
| Certificate delivery | Each service mounts SPIRE agent socket, calls Workload API | Same (hostPath or CSI driver) |
| Trust bundle | SPIRE server bundle, fetched at boot | Same, distributed via ConfigMap or CSI |
| Rotation | Automatic via SPIRE Agent (default 1-hour SVIDs) | Same |
| Dev mode fallback | `SPIFFE_MODE=dev` (header injection, no TLS) | Not available in K8s |

**Docker Compose mTLS implementation:**

The complexity of mTLS in Docker Compose is real (BA Risk #3). The approach:

1. Each service container mounts the SPIRE agent socket at `/tmp/spire-agent/public/api.sock` (already done for gateway).
2. Each service uses the Go SPIFFE Workload API (`github.com/spiffe/go-spiffe/v2/workloadapi`) to obtain an X.509 SVID and trust bundle.
3. The gateway's HTTP server and reverse proxy use `tlsconfig.TLSServerConfig()` and `tlsconfig.TLSClientConfig()` from `go-spiffe` to configure TLS.
4. SPIKE Nexus already speaks mTLS natively (it uses SPIRE for identity).
5. KeyDB requires TLS certificates written to disk; a sidecar or init script fetches the SVID and writes PEM files for KeyDB's `--tls-*` flags.

**CLI setup handles this transparently (Designer requirement P3: Progressive Disclosure):**
- `make setup` in `SPIFFE_MODE=dev` skips mTLS (header injection, HTTP). This is the default.
- `make setup` in `SPIFFE_MODE=prod` enables mTLS. The CLI verifies SPIRE agent is healthy and all services can fetch SVIDs before starting the stack.

**Gateway code changes:**
- Add `SPIFFETrustDomain` to `Config` (default: `poc.local`).
- In `SPIFFE_MODE=prod`, the gateway's `http.Server` uses `tlsconfig.TLSServerConfig()`.
- The reverse proxy's transport uses `tlsconfig.TLSClientConfig()` with the upstream's expected SPIFFE ID.
- The `SPIKENexusRedeemer` (ADR-001) always uses mTLS to SPIKE Nexus regardless of mode.

**Alternatives rejected:**
- cert-manager: Introduces a second CA alongside SPIRE. Two trust roots is worse than one. cert-manager is appropriate for PKI that is NOT SPIFFE-based; here, everything is SPIFFE.
- Manual certificate generation scripts: Fragile, no rotation, poor DX.
- Linkerd/Istio service mesh for mTLS: Massive dependency for a reference architecture POC. The mesh would obscure the security patterns we are demonstrating.

**Trade-offs accepted:**
- KeyDB requires filesystem-based TLS certs (it does not speak the Workload API). A small helper script or init container fetches the SVID and writes PEM files. This is acceptable overhead.
- Dev mode (`SPIFFE_MODE=dev`) remains available for quick evaluation where mTLS overhead is unwanted. The CLI clearly warns that dev mode uses header injection and is NOT secure.

---

### ADR-004: OTel Instrumentation -- Per-Middleware Spans

**Decision:** The gateway emits OpenTelemetry spans for every middleware layer using `go.opentelemetry.io/otel`. Each request produces one parent span with 13 child spans (one per middleware), plus additional spans for proxy and response firewall.

**Where spans are created:**

Each middleware function (`middleware.SPIFFEAuth`, `middleware.AuditLog`, `middleware.DLPMiddleware`, etc.) creates a child span at the start of its handler function. The span is ended when the handler returns (via `defer span.End()`).

```go
// Example: DLPMiddleware instrumentation
func DLPMiddleware(next http.Handler, scanner DLPScanner) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx, span := tracer.Start(r.Context(), "gateway.dlp_scan",
            trace.WithAttributes(
                attribute.Int("mcp.gateway.step", 7),
                attribute.String("mcp.gateway.middleware", "dlp_scan"),
            ),
        )
        defer span.End()

        // ... existing DLP logic ...

        span.SetAttributes(
            attribute.Bool("mcp.dlp.has_credentials", result.HasCredentials),
            attribute.Bool("mcp.dlp.has_pii", result.HasPII),
            attribute.StringSlice("mcp.dlp.flags", result.Flags),
            attribute.String("mcp.result", decision),
        )

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Tracer initialization:**

A package-level tracer is initialized in `internal/gateway/middleware/otel.go`:

```go
var tracer = otel.Tracer("mcp-security-gateway",
    trace.WithInstrumentationVersion("2.0.0"),
)
```

The OTLP exporter is configured in `cmd/gateway/main.go` (or gateway `New()`) using environment variables:
- `OTEL_EXPORTER_OTLP_ENDPOINT` (default: `http://otel-collector:4317`)
- `OTEL_SERVICE_NAME` (default: `mcp-security-gateway`)

**Cross-service context propagation:**

W3C Trace Context (`traceparent` / `tracestate` headers) is propagated automatically:
1. The gateway's reverse proxy transport injects `traceparent` into outbound requests to MCP servers.
2. SPIKE Nexus supports trace context propagation natively (it is a Go service using the standard OTel SDK).
3. The OTel Collector receives spans from all services and forwards them to Phoenix.

**Span attribute schema (contract, per DESIGN.md Section 4.3.3):**

All gateway spans include these attributes:

| Attribute | Type | Source |
|-----------|------|--------|
| `mcp.gateway.step` | int | Hardcoded per middleware |
| `mcp.gateway.middleware` | string | Hardcoded per middleware |
| `mcp.session_id` | string | From context (step 8) |
| `mcp.decision_id` | string | From context (step 4) |
| `mcp.trace_id` | string | OTel trace ID |
| `mcp.spiffe_id` | string | From context (step 3) |
| `mcp.tool` | string | From parsed MCP request |
| `mcp.result` | string | `allowed` / `denied` / `flagged` |
| `mcp.reason` | string | Reason for decision |

**Docker Compose changes:**
- Gateway adds `OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317` and `OTEL_SERVICE_NAME=mcp-security-gateway` to its environment.
- No collector config changes needed -- it already receives OTLP gRPC on 4317 and exports to Phoenix.

**Alternatives rejected:**
- Metrics-only (no traces): Does not satisfy the "trace a single request through all 13 middleware layers" requirement (Ops persona, DESIGN.md Section 1.4).
- Jaeger direct export: Would bypass the OTel Collector, losing the pipeline flexibility.
- Logging-based "traces": Not queryable, not visualizable, does not integrate with Phoenix.

---

### ADR-005: Cosign Signature Verification -- K8s Only

**Decision:** Container image signature verification via cosign is scoped to Kubernetes only. Docker Compose builds from source; the supply chain IS the source code.

**Deployment model (K8s):**

```
+----------------------------+
| sigstore/policy-controller |
| (Admission Webhook)        |
+----------------------------+
         |
         | ValidatingWebhookConfiguration
         |
         v
+----------------------------+
| K8s API Server             |
| (Pod create/update)        |
+----------------------------+
         |
         | OPA Gatekeeper also runs
         | (digest pinning, registry allowlist)
         v
+----------------------------+
| Pod Admitted (or Rejected) |
+----------------------------+
```

**Interaction with OPA Gatekeeper:**

OPA Gatekeeper and sigstore/policy-controller are complementary, not competing:
- **OPA Gatekeeper ConstraintTemplates** (already implemented in Phase 1): Enforce digest pinning (`require-image-digest`) and registry allowlist (`require-image-signature` -- naming is misleading; it enforces registry prefix, not cryptographic signatures).
- **sigstore/policy-controller**: Performs actual cryptographic cosign signature verification. It verifies that the image was signed by the expected OIDC identity (GitHub Actions workflow).

Both run as admission webhooks. Order does not matter -- both must pass for the pod to be admitted.

**Docker Compose: No cosign verification.** Images are built locally from source (`docker compose build`). The supply chain trust anchor is the source code in the repository. Attempting cosign verification on locally-built images would add complexity without security benefit (you would be verifying images you just built).

**Alternatives rejected:**
- cosign verification at Docker Compose build time: Requires a signing key and signing step for local builds. This is a production CI/CD concern, not a local development concern.
- Notary v2 / Docker Content Trust: Less mature, less community adoption than cosign.

---

### ADR-006: Registry Hot-Reload with Attestation

**Decision:** Tool and UI resource registries support hot-reload via filesystem watch (`fsnotify`) with mandatory signature verification before loading.

**Design:**

```
+-------------------+     +-------------------+     +-------------------+
| Registry YAML     | --> | Signature File    | --> | Gateway loads     |
| (tool-registry.   |     | (tool-registry.   |     | only if sig valid |
| yaml)             |     | yaml.sig)         |     |                   |
+-------------------+     +-------------------+     +-------------------+
```

**Attestation mechanism:**

1. Registry files (YAML) are accompanied by a detached signature file (`<filename>.sig`).
2. The signature is created using `cosign sign-blob` with a local key or OIDC identity.
3. On filesystem change, the gateway:
   a. Reads the new registry file.
   b. Reads the corresponding `.sig` file.
   c. Verifies the signature against the configured public key or OIDC identity.
   d. If verification passes, atomically swaps the in-memory registry.
   e. If verification fails, logs a critical alert, keeps the old registry, and emits an audit event.

**Changes to existing types:**

`ToolRegistry` (in `internal/gateway/middleware/`) gains:
- `Watch()` method that starts an `fsnotify` watcher on the registry YAML file.
- `verifySignature(data []byte, sig []byte) error` method.
- `TOOL_REGISTRY_PUBLIC_KEY` env var for the verification key.
- Atomic swap via `sync.RWMutex` (already exists on `ToolRegistry`).

`UIResourceRegistry` follows the same pattern.

**When attestation is disabled (default for dev):**
If `TOOL_REGISTRY_PUBLIC_KEY` is empty, hot-reload works without signature verification but emits a warning at startup and on every reload: "Registry hot-reload is enabled WITHOUT attestation. Unsigned updates will be accepted."

**Alternatives rejected:**
- OPA bundle signing model extended to registries: OPA bundles use a different signing format. Reusing it would couple the registry to OPA internals.
- Git-based registry with signed commits: Over-engineered for a file-based registry. Better suited for a registry service (Phase 3).
- No hot-reload (restart required): Poor operational DX. Enterprise evaluators expect runtime reconfiguration.

---

### ADR-007: Deep Scan Configuration -- Setup-Time Fail-Closed/Fail-Open

**Decision:** Deep scan behavior is fully configured at setup time via the CLI wizard. Three parameters are stored in `.env`:

| Parameter | Env Var | Default | Description |
|-----------|---------|---------|-------------|
| API key | `GROQ_API_KEY` | (empty) | Groq API key for Prompt Guard 2 |
| Fallback policy | `DEEP_SCAN_FALLBACK` | `fail_closed` | What to do when guard model is unavailable |
| Timeout | `DEEP_SCAN_TIMEOUT` | `5` | Seconds before applying fallback policy |

**Configuration flow:**

```
CLI Setup                    .env file                 Gateway Config
+-----------+      +--------------------+      +-------------------+
| Questions |  --> | GROQ_API_KEY=...   |  --> | DeepScanFallback  |
| with      |      | DEEP_SCAN_FALLBACK |      | (fail_closed or   |
| defaults  |      | =fail_closed       |      |  fail_open)       |
+-----------+      | DEEP_SCAN_TIMEOUT  |      +-------------------+
                   | =5                 |
                   +--------------------+
```

**Runtime behavior:**

1. If `GROQ_API_KEY` is empty, deep scan is fully disabled. The middleware becomes a pass-through. The CLI warns: "Deep scan is DISABLED. Prompt injection detection relies on DLP regex only."
2. If `GROQ_API_KEY` is set, deep scan dispatches to Groq's Prompt Guard 2 API.
3. If Groq returns an error (rate limit, network, timeout):
   - `fail_closed`: Request is blocked with error code `deepscan_unavailable_fail_closed`.
   - `fail_open`: Request is allowed. An audit event records that deep scan was skipped with reason.

**Prompt chunking for large payloads:**
The Groq Prompt Guard 2 model has a context window of 512 tokens. For payloads exceeding this:
1. Split the payload into overlapping chunks (512 tokens with 64-token overlap).
2. Send each chunk as a separate Groq API call (parallelized, bounded to 3 concurrent).
3. If ANY chunk is flagged, the entire request is flagged.
4. Chunk results are aggregated; the highest injection/jailbreak probability across chunks is used for the step-up gating risk score.

**Gateway code changes:**
- Add `DeepScanFallback` to `Config` (env: `DEEP_SCAN_FALLBACK`, default: `fail_closed`).
- `DeepScanner.Dispatch()` gains fallback logic based on `DeepScanFallback` config.
- `DeepScanner.analyzeWithGroq()` gains chunking logic for payloads > 512 tokens.
- Step-up gating (step 9) already consumes deep scan results; no change to the step-up interface.

---

### ADR-008: Compliance Automation Architecture

**Decision:** The compliance report generator is a standalone Python CLI tool that reads audit logs, policy configs, and test results to produce XLSX, CSV, and PDF outputs. It does NOT import any Go code; it reads artifacts.

**Architecture:**

```
make compliance-report
  |
  +-- 1. make test-e2e         (runs E2E suite, captures output to reports/evidence/)
  |
  +-- 2. python3 tools/compliance/generate.py
         |
         +-- reads: /tmp/audit.jsonl (audit log)
         +-- reads: config/opa/mcp_policy.rego (OPA policies)
         +-- reads: config/tool-registry.yaml (tool registry)
         +-- reads: config/risk_thresholds.yaml (risk config)
         +-- reads: reports/evidence/e2e-results.txt (test output)
         +-- reads: tools/compliance/control_taxonomy.yaml (control-to-framework mapping)
         |
         +-- writes: reports/compliance-YYYY-MM-DD/
                       compliance-report.xlsx
                       compliance-report.csv
                       compliance-summary.pdf
                       evidence/
                         audit-log-excerpt.jsonl
                         e2e-test-results.txt
                         policy-configs/
```

**Control taxonomy (DESIGN.md Section 4.2.4):**

The mapping between gateway controls and compliance frameworks lives in `tools/compliance/control_taxonomy.yaml`:

```yaml
controls:
  - id: GW-AUTH-001
    name: Agent Identity Verification (SPIFFE/mTLS)
    middleware: spiffe_auth
    step: 3
    frameworks:
      soc2: CC6.1
      iso27001: A.9.2.1
      gdpr: Art. 32
    evidence_type: audit_log
    evidence_query: ".action == 'mcp_request' and .spiffe_id != ''"
```

**Why Python (not Go):**
- openpyxl (XLSX generation), fpdf2 (PDF generation), and csv (stdlib) are mature Python libraries with no Go equivalents at the same quality level.
- The compliance tool is an offline artifact generator, not a runtime component. It has zero coupling to the gateway's Go code.
- The Designer's persona Eliana runs `make compliance-report`; she does not care about the implementation language.

**Why not a Go CLI:**
- Go's XLSX and PDF libraries (excelize, gofpdf) exist but are less mature for complex formatting (conditional formatting, sheet protection, cell styles). Python's openpyxl is the de facto standard.

---

### ADR-009: Docker Compose vs K8s Pattern Audit

**Decision:** All controls are classified into three categories. This classification is documented in `docs/deployment-patterns.md` and in the compliance report.

| Category | Docker Compose | K8s | Examples |
|----------|---------------|-----|---------|
| **Universal** | Yes | Yes | 13-middleware chain, DLP, OPA, audit, session, token substitution, deep scan, rate limiting, circuit breaker, tool registry, response firewall |
| **K8s-native** | N/A (documented) | Yes | NetworkPolicies, PodSecurityAdmission, cosign admission, OPA Gatekeeper admission, SPIRE node attestation, encrypted PVCs |
| **K8s-equivalent** | Docker equivalent | K8s native | mTLS (SPIRE SVIDs both), session persistence (KeyDB both), rate limiting (KeyDB both) |

**Docker Compose equivalents for K8s-native controls:**

| K8s Control | Docker Compose Equivalent | Coverage |
|-------------|--------------------------|----------|
| NetworkPolicy (default deny) | Docker network isolation (bridge network) | Partial -- no egress control |
| PodSecurityAdmission | Dockerfile best practices (non-root, read-only rootfs) | Partial -- no enforcement |
| OPA Gatekeeper admission | N/A (images built from source) | Unnecessary -- supply chain is source |
| Cosign signature verification | N/A (images built from source) | Unnecessary -- supply chain is source |
| Encrypted PVCs | Docker volumes (ephemeral in dev) | N/A -- no at-rest encryption in dev |
| SPIRE node attestation | Docker attestor (container label matching) | Equivalent |

**The pattern audit document explicitly states what is NOT covered in Docker Compose and why.** This is the "honest limitations" principle from DESIGN.md Section 6.2.

---

### ADR-010: Local K8s Deployment via Kustomize Overlay

**Decision:** A dedicated Kustomize overlay at `infra/eks/overlays/local/kustomization.yaml` adapts the EKS manifests for Docker Desktop kubeadm.

**Modifications from EKS:**

| EKS Resource | Local K8s Replacement | Rationale |
|-------------|----------------------|-----------|
| ALB Ingress Controller | NodePort Service | No AWS ALB in local K8s |
| IRSA (IAM Roles for SA) | Hardcoded credentials in Secrets (dev only) | No AWS IAM in local K8s |
| EBS CSI StorageClass | Default `hostpath` StorageClass | No EBS in local K8s |
| Route53 DNS | `localhost` / `*.local` | No cloud DNS |
| 3-AZ node topology | Single node | Docker Desktop runs one node |
| SPIRE k8s node attestor | SPIRE join token attestor | No cloud metadata service |

**SPIRE attestation locally:**
The EKS manifests use the `k8s_psat` (Projected Service Account Token) node attestor. Local K8s uses `join_token` attestor (same as Docker Compose). A `spire-token-generator` Job creates fresh join tokens at deploy time.

**Resource limits:**
The local overlay reduces resource requests/limits to fit on a laptop:
- Gateway: 100m CPU / 128Mi memory (down from 500m / 512Mi)
- SPIKE Nexus: 50m CPU / 64Mi (unchanged)
- KeyDB: 50m CPU / 64Mi
- SPIRE: 100m CPU / 128Mi each

**Minimum hardware:** 4 CPU cores, 8GB RAM (documented in `docs/getting-started/prerequisites.md`).

---

## 3. Component Architecture

### 3.1 Gateway Core (Go)

The gateway remains a single Go binary. Phase 2 adds:

| New Dependency | Purpose | Import Path |
|---------------|---------|-------------|
| OTel SDK | Span creation, export | `go.opentelemetry.io/otel` |
| go-redis | KeyDB client | `github.com/redis/go-redis/v9` |
| go-spiffe | Workload API, TLS config | `github.com/spiffe/go-spiffe/v2` |
| spike-sdk-go | SPIKE Nexus client | `github.com/spiffe/spike-sdk-go` |
| fsnotify | Registry hot-reload | `github.com/fsnotify/fsnotify` |

**Config additions (all via environment variables, all with defaults):**

| Env Var | Default | Purpose |
|---------|---------|---------|
| `SPIKE_NEXUS_URL` | `https://spike-nexus:8443` | SPIKE Nexus endpoint |
| `KEYDB_URL` | (empty -- in-memory fallback) | KeyDB connection string |
| `KEYDB_POOL_MIN` | `5` | Minimum connection pool size |
| `KEYDB_POOL_MAX` | `20` | Maximum connection pool size |
| `SESSION_TTL` | `3600` | Session data TTL in seconds |
| `DEEP_SCAN_FALLBACK` | `fail_closed` | Deep scan fallback policy |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | OTel collector endpoint |
| `OTEL_SERVICE_NAME` | `mcp-security-gateway` | Service name for traces |
| `TOOL_REGISTRY_PUBLIC_KEY` | (empty -- no attestation) | Public key for registry signature verification |
| `SPIFFE_TRUST_DOMAIN` | `poc.local` | SPIFFE trust domain |

### 3.2 Middleware Chain (Unchanged Order)

The 13-step middleware chain order is a security invariant and does NOT change in Phase 2:

| Step | Middleware | Phase 2 Changes |
|------|-----------|-----------------|
| 1 | Request Size Limit | OTel span added |
| 2 | Body Capture | OTel span added |
| 3 | SPIFFE Auth | OTel span added; mTLS mode (SVID verification) when `SPIFFE_MODE=prod` |
| 4 | Audit Logging | OTel span added |
| 5 | Tool Registry Verify | OTel span added; hot-reload with attestation |
| 6 | OPA Policy | OTel span added |
| 7 | DLP Scan | OTel span added |
| 8 | Session Context | OTel span added; KeyDB backend (cross-request persistence) |
| 9 | Step-Up Gating | OTel span added |
| 10 | Deep Scan Dispatch | OTel span added; Groq API integration with chunking and fallback |
| 11 | Rate Limiting | OTel span added; KeyDB backend (distributed) |
| 12 | Circuit Breaker | OTel span added |
| 13 | Token Substitution | OTel span added; SPIKE Nexus backend (real secret redemption) |

**Security invariant (carried from Phase 1):** Token substitution MUST remain step 13 (innermost, last before proxy). No middleware between step 13 and the proxy may inspect request bodies. This ensures no middleware ever sees raw secrets.

### 3.3 SPIKE Nexus Service

**Docker Compose definition:**

```yaml
spike-nexus:
  build:
    context: .
    dockerfile: build/docker/Dockerfile.spike-nexus
    # Builds from github.com/spiffe/spike nexus.Dockerfile
    # or pulls ghcr.io/spiffe/spike-nexus:0.8.0
  image: spike-nexus:latest
  container_name: spike-nexus
  hostname: spike-nexus
  depends_on:
    spire-agent:
      condition: service_healthy
  volumes:
    - spire-agent-socket:/tmp/spire-agent/public:ro
    - spike-data:/data
  ports:
    - "8443:8443"
  environment:
    - SPIKE_NEXUS_MODE=token
    - SPIKE_NEXUS_LOG_LEVEL=info
    - SPIKE_NEXUS_ADDR=:8443
    - SPIKE_NEXUS_TRUST_DOMAIN=poc.local
    - SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
  networks:
    - agentic-net
  healthcheck:
    test: ["CMD", "wget", "--spider", "-q", "-k", "https://localhost:8443/healthz"]
    interval: 10s
    timeout: 5s
    retries: 5
    start_period: 15s

spike-bootstrap:
  build:
    context: .
    dockerfile: build/docker/Dockerfile.spike-bootstrap
  image: spike-bootstrap:latest
  container_name: spike-bootstrap
  depends_on:
    spike-nexus:
      condition: service_healthy
  volumes:
    - spire-agent-socket:/tmp/spire-agent/public:ro
  environment:
    - SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/public/api.sock
    - SPIKE_NEXUS_ADDR=https://spike-nexus:8443
  networks:
    - agentic-net
  restart: "no"  # One-shot bootstrap
```

**SPIRE registration entries for SPIKE:**

```
# SPIKE Nexus identity
spire-server entry create \
  -spiffeID spiffe://poc.local/spike/nexus \
  -parentID spiffe://poc.local/spire/agent \
  -selector docker:label:spiffe-id:spike-nexus

# SPIKE Bootstrap identity (for initial root key delivery)
spire-server entry create \
  -spiffeID spiffe://poc.local/spike/bootstrap \
  -parentID spiffe://poc.local/spire/agent \
  -selector docker:label:spiffe-id:spike-bootstrap
```

### 3.4 KeyDB Service

See ADR-002 for data model. Docker Compose definition included in that section.

### 3.5 Compliance Report Generator

See ADR-008 for architecture. The tool lives at `tools/compliance/` and is invoked via `make compliance-report`.

### 3.6 CLI Setup Wizard

The CLI setup wizard is a shell script (`scripts/setup.sh`) that:
1. Checks prerequisites (Docker, Docker Compose, Go, optional tools).
2. Asks configuration questions with defaults (per DESIGN.md Section 4.1.2).
3. Generates `.env` from answers.
4. Prints security posture summary (per DESIGN.md Section 4.1.3).
5. Optionally runs `docker compose up -d` and post-startup smoke test.

It is invoked via `make setup`.

---

## 4. Security Architecture

### 4.1 Authentication and Authorization

| Layer | Mechanism | Enforcement Point |
|-------|-----------|-------------------|
| Workload identity | SPIFFE X.509 SVIDs via SPIRE | Step 3 (SPIFFE Auth middleware) |
| Tool authorization | OPA Rego policies (embedded) | Step 6 (OPA Policy middleware) |
| Secret access | SPIKE token scope validation | Step 13 (Token Substitution middleware) |
| K8s admission | OPA Gatekeeper + sigstore/policy-controller | K8s API server |

### 4.2 Data Protection

| Data | At Rest | In Transit | Retention |
|------|---------|-----------|-----------|
| Secrets (SPIKE) | AES-256-GCM encrypted (Nexus) or OpenBAO backend | mTLS (SVID) | Until explicitly deleted |
| Session context (KeyDB) | Ephemeral (Docker volume) or encrypted PVC (K8s) | TLS (prod mode) | TTL-based (default 1 hour) |
| Audit logs | Hash-chained JSONL | mTLS to S3 (K8s) | Indefinite (compliance evidence) |
| Request/response bodies | Never stored persistently | mTLS between all services | Not retained |

### 4.3 Security Boundaries

```
+--------------------------------------------------+
|              TRUST BOUNDARY                       |
|                                                   |
|  Agent  -- mTLS -->  Gateway  -- mTLS -->  SPIKE  |
|                       |                           |
|                       +-- mTLS -->  MCP Server    |
|                       +-- mTLS -->  KeyDB         |
|                       +-- HTTP -->  OTel Collector |
|                                     (internal     |
|                                      telemetry,   |
|                                      not secrets) |
+--------------------------------------------------+
```

The OTel Collector is the one service that does NOT require mTLS. It receives only telemetry data (spans, metrics), never secrets or sensitive request payloads. The spans contain middleware decisions and timing, not request bodies. This is a deliberate exception to reduce operational complexity.

### 4.4 Compliance Requirements

Mapped in BUSINESS.md Section 7. The compliance report generator (ADR-008) automates evidence collection for:
- SOC 2 Type II (CC6.1, CC6.5, CC6.6, CC6.7, CC7.1, CC7.2)
- ISO 27001 (A.8.2.1, A.9.2.1, A.9.4.1, A.10.1.1, A.12.2.1, A.12.4.1, A.13.1.1, A.14.2.7)
- CCPA/CPRA (1798.105, 1798.150)
- GDPR (Art. 17, 25, 28, 30, 32)

### 4.5 Threat Model

The threat model from the reference architecture (Section 2) is fully addressed by Phase 2:

| Threat | Mitigation | Phase 2 Status |
|--------|-----------|----------------|
| Credential exfiltration by LLM | Late-binding SPIKE tokens (step 13) | P0: SPIKE Nexus activation |
| Tool poisoning / rug-pull | SHA-256 hash verification (step 5) + hot-reload attestation | Proven + ADR-006 |
| Prompt injection | DLP regex (step 7) + Groq Prompt Guard 2 (step 10) + step-up gating (step 9) | ADR-007 deep scan config |
| Cross-request exfiltration | KeyDB session persistence (step 8) | ADR-002 |
| Plaintext internal traffic | mTLS via SPIRE SVIDs | ADR-003 |
| Supply chain (K8s) | cosign + OPA Gatekeeper admission | ADR-005 |
| Registry poisoning | Signed registry updates (ADR-006) | ADR-006 |

---

## 5. Deployment Architecture

### 5.1 Docker Compose (Primary Evaluation Target)

Services in Phase 2:

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| spire-server | ghcr.io/spiffe/spire-server:1.10.0 | 8080-8081 | Identity control plane |
| spire-agent | spire-agent-wrapper:latest (built) | -- | Workload attestation |
| spire-token-generator | spire-token-generator:latest (built) | -- | One-shot join token |
| spike-nexus | spike-nexus:latest (built from SPIKE) | 8443 | Secrets management |
| spike-bootstrap | spike-bootstrap:latest (built) | -- | One-shot root key init |
| keydb | eqalpha/keydb:6.3.4 | 6379 | Session + rate limiting |
| otel-collector | otel/opentelemetry-collector-contrib:latest | 4317-4318 | Telemetry pipeline |
| phoenix | arizephoenix/phoenix:latest | 6006 | Trace visualization |
| mcp-security-gateway | mcp-security-gateway:latest (built) | 9090 | Security enforcement |

### 5.2 Local K8s (Docker Desktop kubeadm)

Same services, deployed via Kustomize overlay `infra/eks/overlays/local/`. See ADR-010.

### 5.3 EKS (Validated Offline)

Existing Phase 1 manifests in `infra/eks/`. Phase 2 updates:
- SPIKE Nexus image version updated to 0.8.0.
- sigstore/policy-controller admission webhook added.
- KeyDB StatefulSet added.
- OTel Collector ConfigMap updated for gateway span ingestion.

---

## 6. Integration Points

Every integration point between components is explicitly documented here. This is the wiring contract that the Sr. PM will use to create walking skeleton stories.

### 6.1 Gateway <-> SPIKE Nexus

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> Nexus | HTTPS (mTLS via SVID) | `POST /v1/store/secret/get` | Token ref, requesting SPIFFE ID |
| Nexus -> Gateway | HTTPS response | -- | Secret value (AES-256-GCM decrypted) |
| Bootstrap -> Nexus | HTTPS (mTLS via SVID) | `POST /v1/store/secret/put` | Initial secrets |
| CLI -> Nexus (via Pilot) | HTTPS (mTLS via SVID) | `spike secret put <path> <key=value>` | Secret creation |

### 6.2 Gateway <-> KeyDB

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> KeyDB | Redis protocol (TLS in prod) | `redis://keydb:6379` | Session CRUD, rate limit tokens |
| Gateway -> KeyDB | -- | -- | Connection pool: min 5, max 20 |

### 6.3 Gateway <-> OTel Collector

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> Collector | OTLP gRPC | `otel-collector:4317` | Spans with middleware attributes |
| Collector -> Phoenix | OTLP gRPC | `phoenix:4317` | Forwarded spans |

### 6.4 Gateway <-> SPIRE Agent

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> Agent | Unix socket | `/tmp/spire-agent/public/api.sock` | Workload API (X.509 SVID fetch) |

### 6.5 Gateway <-> MCP Server

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> MCP Server | HTTP(S) (mTLS in prod) | Configurable upstream URL | MCP JSON-RPC with substituted secrets |

### 6.6 Gateway <-> Groq API

| Direction | Protocol | Endpoint | Data |
|-----------|----------|----------|------|
| Gateway -> Groq | HTTPS | `https://api.groq.com/openai/v1/chat/completions` | Prompt Guard 2 classification request |
| Groq -> Gateway | HTTPS response | -- | Injection/jailbreak probabilities |

---

## 7. Error Response Architecture

Phase 2 standardizes all gateway error responses to the unified JSON envelope defined in DESIGN.md Section 4.4.2. This is a **breaking change** from Phase 1.

**Migration path:** All middleware error responses are refactored to use a shared `WriteGatewayError(w, err GatewayError)` function in `internal/gateway/middleware/errors.go`. The `GatewayError` struct maps directly to the JSON envelope.

```go
type GatewayError struct {
    Code           string            `json:"code"`
    Message        string            `json:"message"`
    Middleware     string            `json:"middleware"`
    MiddlewareStep int               `json:"middleware_step"`
    DecisionID     string            `json:"decision_id"`
    TraceID        string            `json:"trace_id"`
    Details        map[string]any    `json:"details,omitempty"`
    Remediation    string            `json:"remediation,omitempty"`
    DocsURL        string            `json:"docs_url,omitempty"`
}
```

Error codes are enumerated in DESIGN.md Section 4.4.3. The full catalog lives in `internal/gateway/middleware/error_codes.go`.

---

## 8. Diagrams

### 8.1 Request Flow (Full Middleware Chain with OTel)

```
Agent Request
    |
    v
[1. Size Limit] ---- span: gateway.request_size_limit ---+
    |                                                      |
[2. Body Capture] - span: gateway.body_capture -----------+
    |                                                      |
[3. SPIFFE Auth] -- span: gateway.spiffe_auth ------------+
    |                                                      |
[4. Audit Log] ---- span: gateway.audit_log --------------+  --> Audit JSONL
    |                                                      |
[5. Tool Reg] ----- span: gateway.tool_registry_verify ---+
    |                                                      |
[6. OPA Policy] --- span: gateway.opa_policy -------------+
    |                                                      |
[7. DLP Scan] ----- span: gateway.dlp_scan ---------------+
    |                                                      |
[8. Session Ctx] -- span: gateway.session_context --------+  --> KeyDB
    |                                                      |
[9. Step-Up] ------ span: gateway.step_up_gating ---------+
    |                                                      |
[10. Deep Scan] --- span: gateway.deep_scan_dispatch -----+  --> Groq API
    |                                                      |
[11. Rate Limit] -- span: gateway.rate_limit -------------+  --> KeyDB
    |                                                      |
[12. Circuit Brk] - span: gateway.circuit_breaker --------+
    |                                                      |
[13. Token Sub] --- span: gateway.token_substitution -----+  --> SPIKE Nexus
    |                                                      |
[Proxy] ----------- span: gateway.proxy ------------------+  --> MCP Server
    |                                                      |
[Resp Firewall] --- span: gateway.response_firewall ------+
    |                                                      |
    v                                                      v
Agent Response                                    OTel Collector --> Phoenix
```

### 8.2 SPIKE Nexus Token Lifecycle

```
                          SETUP TIME
                          ----------
Admin (via CLI setup):
  spike secret put external-apis/groq-key value=$GROQ_API_KEY

                          RUNTIME
                          -------
Agent:
  1. spike secret get external-apis/groq-key --mode=token
     --> receives $SPIKE{ref:7f3a9b2c,exp:300,scope:header.Authorization.api.groq.com}

  2. Tool call to gateway with token in request body

Gateway (step 13):
  3. Parse $SPIKE{ref:7f3a9b2c} from request body
  4. Validate: ownership (SPIFFE ID match), expiry, scope
  5. Redeem: mTLS call to SPIKE Nexus /v1/store/secret/get
  6. Substitute: replace token with real secret in outbound request
  7. Audit: log substitution event (ref, spiffe_id, scope -- NOT secret value)

MCP Server:
  8. Receives request with real secret (e.g., Authorization: Bearer sk-...)
  9. Makes API call to external service
  10. Returns result to gateway

Gateway:
  11. Response firewall processes response
  12. Returns to agent (agent NEVER saw the real secret)
```

### 8.3 Session Persistence Flow (KeyDB)

```
Request 1 (read sensitive data):
  Agent --> Gateway --> [Step 8: Session Context]
                           |
                           +-- KeyDB SET session:{spiffe}:{sess} {actions: [...]}
                           +-- KeyDB RPUSH session:{spiffe}:{sess}:actions {action}
                           |
                           +--> Request proceeds

Request 2 (external send):
  Agent --> Gateway --> [Step 8: Session Context]
                           |
                           +-- KeyDB GET session:{spiffe}:{sess}
                           +-- KeyDB LRANGE session:{spiffe}:{sess}:actions -5 -1
                           |
                           +-- DetectsExfiltrationPattern()
                           |   (checks: was sensitive data read in recent actions?
                           |    is this an external target?)
                           |
                           +--> BLOCKED: 403 Exfiltration pattern detected
```

---

## 9. Walking Skeleton Recommendation

The thinnest E2E slice for Phase 2 (the walking skeleton) should prove:

1. SPIKE Nexus boots in Docker Compose and accepts a secret via Pilot CLI.
2. An agent receives a SPIKE token reference.
3. The gateway's token substitution middleware redeems the token via mTLS to SPIKE Nexus.
4. The substituted secret appears in the outbound request to the MCP server.
5. The agent's audit trail shows only the opaque token, never the real secret.
6. A per-middleware OTel span appears in Phoenix.

This skeleton validates ADR-001, ADR-003 (mTLS to Nexus), and ADR-004 (OTel) in a single vertical slice. Everything else (KeyDB, compliance, deep scan, hot-reload) layers on top.

---

## 10. Phase 3 Extension Points

These are NOT Phase 2 scope but are architecturally preserved:

| Phase 3 Feature | How Phase 2 Prepares |
|-----------------|---------------------|
| Streaming MCP | OTel spans support long-lived spans. Error format works for streaming. |
| Plugin ecosystem | Tool registry hot-reload with attestation is the foundation for dynamic plugin registration. |
| Additional compliance frameworks | Control taxonomy YAML is extensible without code changes. |
| T5-small fine-tuning for offline deep scan | Deep scan interface accepts any model backend. Groq is pluggable. |
| Multi-agent orchestration | SPIFFE ID hierarchy supports agent-to-agent trust. OPA policies support delegation grants. |
| SPIKE Keepers (HA) | SPIKE Nexus architecture supports Keepers natively. Nexus is a single-replica deployment; Keepers add Shamir sharding. |

---

## 11. Related Architecture Documents

- [BUSINESS.md](BUSINESS.md) -- Business outcomes, priorities, constraints
- [DESIGN.md](DESIGN.md) -- User personas, journeys, interface designs
- [current-state-and-roadmap.md](current-state-and-roadmap.md) -- Phase 1 state and gaps
- [e2e-validation-report.md](e2e-validation-report.md) -- Phase 1 E2E results
- Reference Architecture: `../agentic-ai-security-reference-architecture.md` (v2.2)
- EKS IaC spike recommendation: `docs/eks-iac-spike-recommendation.md`

---

## 12. Decision Log Summary

| ADR | Decision | Priority (from BA) |
|-----|----------|-------------------|
| ADR-001 | SPIKE Nexus three-tier backend, `vsecm/spike-nexus:0.8.0` -> `ghcr.io/spiffe/spike-nexus:0.8.0` | P0-1 |
| ADR-002 | KeyDB for session persistence + distributed rate limiting, GDPR-compliant | P1-3 |
| ADR-003 | SPIRE-native SVIDs for mTLS (no cert-manager) | P1-4 |
| ADR-004 | OTel per-middleware spans with `go.opentelemetry.io/otel` | P1-2 |
| ADR-005 | Cosign signature verification K8s-only via sigstore/policy-controller | P1-6 |
| ADR-006 | Registry hot-reload with cosign-blob attestation | P2-5 |
| ADR-007 | Deep scan configurable fail-closed/fail-open at setup time, prompt chunking | P0-2, P1-7 |
| ADR-008 | Python CLI compliance report generator (XLSX/CSV/PDF) | P1-1 |
| ADR-009 | Docker Compose vs K8s pattern audit (three categories) | P2-1 |
| ADR-010 | Local K8s via Kustomize overlay with reduced resources | P1-5 |

---

*This document is the single source of truth for Phase 2 technical architecture. It is validated by the BA (BUSINESS.md) for business alignment and by the Designer (DESIGN.md) for feasibility. Changes require BLT consensus.*
