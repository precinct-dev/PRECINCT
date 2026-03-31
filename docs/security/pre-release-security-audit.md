# PRECINCT Pre-Release Security Audit

**Date:** 2026-03-14
**Auditor:** Automated + Manual Code Review
**Scope:** Full codebase security review covering 7 audit areas
**Branch:** story/OC-1nwr (historical audit branch)

---

## Executive Summary

PRECINCT demonstrates a mature security posture for a pre-release project. The
architecture makes strong use of SPIFFE/SPIRE for zero-trust identity, mTLS for
transport security, OPA for policy enforcement, and DLP for data loss prevention.
This document is a point-in-time assessment of that branch snapshot only; it is
not the authoritative release sign-off for the current `main` branch. Three
high-severity issues were found and fixed in that audit (all Dockerfile non-root
hardening). Several medium and low findings are documented with accepted risk rationale.

---

## 1. OWASP Top 10 Assessment

### 1.1 Injection (A03:2021)

**Status: PASS**

- **SQL Injection:** No SQL database usage detected in the codebase. No `sql.Open`,
  `db.Exec`, or `db.Query` calls. The system uses KeyDB (Redis protocol) which is
  not susceptible to SQL injection.
- **Command Injection:** `exec.Command` usage is present in CLI tooling
  (`internal/precinctcli/`) and test infrastructure. All invocations use explicit command
  arrays (not shell interpolation). No user-supplied input is passed to shell commands.
- **Prompt Injection:** DLP middleware (`internal/gateway/middleware/dlp.go`) includes
  comprehensive prompt injection detection patterns (ignore instructions, DAN mode,
  system prompt overrides). Deep scan guard model provides ML-based secondary analysis.
- **Path Injection:** Fixed `internal/tools/context_fetcher.go` `GetContent()` to
  validate `contentID` against path traversal characters (`/`, `\`, `..`).

### 1.2 Broken Authentication (A07:2021)

**Status: PASS**

- SPIFFE/SPIRE provides cryptographic workload identity via X.509 SVIDs.
- Production mode extracts identity from mTLS client certificates (URI SAN), not headers.
- Dev mode header-based auth (`X-SPIFFE-ID`) requires explicit opt-in via
  `ALLOW_INSECURE_DEV_MODE=true` and is restricted to loopback by default.
- Admin endpoints enforce SPIFFE identity allowlists (`AdminAuthzAllowedSPIFFEIDs`).

### 1.3 Sensitive Data Exposure (A02:2021)

**Status: PASS**

- SPIKE token system uses late-binding secret references (`$SPIKE{ref:...}`) that are
  redeemed at execution time via mTLS to SPIKE Nexus. Secrets never transit in request
  bodies.
- DLP scanner detects credentials (API keys, private keys, passwords) and blocks them
  by default (`credentials=block` policy).
- No secrets or credentials found in committed source files. All hardcoded values in
  `*_test.go` files are test-only placeholders (e.g., "test-key", "test-guard-key-from-env").
- `.gitignore` excludes `.env`, `.env.local`, `.env.*.local`, `.envrc` files.

### 1.4 XML External Entities (A05:2021)

**Status: N/A**

No XML parsing in the codebase. The system uses JSON and YAML exclusively.

### 1.5 Broken Access Control (A01:2021)

**Status: PASS**

- OPA policy engine (`internal/gateway/middleware/opa_engine.go`) enforces tool-level,
  path-based, and identity-based access control.
- Admin endpoints require both SPIFFE identity and explicit allowlist membership.
- Upstream mTLS peer pinning enforces identity allowlists in strict profiles.
- Response firewall uses opaque data handles with TTL to prevent unauthorized data access.

### 1.6 Security Misconfiguration (A05:2021)

**Status: PASS (with accepted risks)**

- Startup conformance checks (`startup_conformance.go`) validate security-critical
  configuration before the gateway accepts traffic.
- Dev mode requires double opt-in (`SPIFFE_MODE=dev` + `ALLOW_INSECURE_DEV_MODE=true`).
- Non-loopback dev binding requires additional `ALLOW_NON_LOOPBACK_DEV_BIND=true`.
- **Accepted Risk (Medium):** The `DemoRugpullAdminEnabled` flag exists for demo
  purposes. It is disabled by default and clearly gated behind an explicit env var.

### 1.7 Cross-Site Scripting (A03:2021)

**Status: N/A**

No HTML template rendering. The gateway is a JSON API. The site (`site/`) serves
static HTML files. The gateway sets Content-Security-Policy headers via the CSP
mediator (`ui_csp_mediator.go`).

### 1.8 Insecure Deserialization (A08:2021)

**Status: PASS**

- JSON unmarshaling uses standard library (`encoding/json`) with typed structs.
- YAML parsing uses `gopkg.in/yaml.v3` with typed structs.
- No use of `gob` or other dangerous serialization formats.
- Request body size is enforced by `RequestSizeLimit` middleware (default 10MB).

### 1.9 Using Components with Known Vulnerabilities (A06:2021)

**Status: PASS**

- `govulncheck ./...` reports no known vulnerabilities.
- `go mod verify` confirms all module checksums match go.sum.
- See Section 7 for full dependency audit.

### 1.10 Insufficient Logging and Monitoring (A09:2021)

**Status: PASS**

- Comprehensive audit logging via `middleware/audit.go` captures every request decision.
- Audit events include SPIFFE ID, decision ID, timestamp, middleware step, and security
  flags.
- OpenTelemetry integration provides distributed tracing across gateway, SPIKE Nexus,
  and upstream services.
- Audit log integrity verification exists (`middleware/audit_verify.go`).

---

## 2. Secret Management

**Status: PASS**

| Check | Result |
|-------|--------|
| SPIKE token references ($SPIKE{ref:...}) | Implemented -- secrets redeemed at execution time via mTLS |
| .env patterns in .gitignore | .env, .env.local, .env.*.local, .envrc all excluded |
| Environment variable handling | Config loaded via `os.Getenv` with defaults; no secrets logged |
| Crypto keys in repo | Only public keys and cosign metadata; private key paths in .gitignore |
| In-memory only secrets | SPIKE secrets redeemed and used in-memory; not persisted to disk |
| Approval signing key | HMAC-SHA256 with minimum 32-byte key enforced in strict profiles |

**No hardcoded credentials found in source code.** All credential-like strings in the
repository are test fixtures in `*_test.go` files.

---

## 3. Input Validation

**Status: PASS**

| Area | Validation |
|------|-----------|
| Request body size | `RequestSizeLimit` middleware enforces max 10MB (configurable) |
| SPIFFE ID format | Validated for `spiffe://` prefix; parsed via `url.Parse` |
| OPA policy files | YAML/Rego parsed with standard libraries; file watcher for hot reload |
| JSON-RPC bodies | Parsed into typed structs; malformed requests rejected |
| Discord webhooks | Ed25519 signature verification before processing |
| Email port | JSON body decoded into typed structs with error handling |
| Path traversal | Fixed: `GetContent()` now validates contentID against traversal characters |
| Header injection | HTTP headers set via Go standard `http.Header.Set()` which sanitizes values |

---

## 4. Authentication / Authorization

**Status: PASS**

| Component | Status |
|-----------|--------|
| SPIFFE/SPIRE integration | Full mTLS via go-spiffe X509Source with automatic SVID rotation |
| mTLS server config | `RequireAndVerifyClientCert` in prod mode; trust bundle from SPIRE |
| mTLS upstream transport | Gateway presents SVID as client cert; validates upstream SVID |
| Token validation | SPIKE tokens parsed and validated with scope/expiry checks |
| OPA policy engine | Embedded OPA evaluates tool access, path access, identity policies |
| Admin endpoint authz | SPIFFE identity allowlist enforcement for all /admin/* paths |
| Upstream peer pinning | Configurable SPIFFE ID allowlist for upstream mTLS connections |
| KeyDB peer pinning | Configurable SPIFFE ID allowlist for KeyDB mTLS connections |
| CLI auth | CLI tools use Docker exec or gateway API (no direct secret handling) |

---

## 5. Supply Chain Security

**Status: PASS**

| Check | Result |
|-------|--------|
| go.sum integrity | `go mod verify` -- all modules verified |
| Container image digests | All Dockerfiles use `@sha256:` digest pinning |
| Cosign directory | `.cosign/` present with README (signing infrastructure ready) |
| Tool registry attestation | Ed25519 signature verification for tool registry YAML (RFA-lo1.4) |
| OPA policy attestation | Ed25519 companion-signature verification for policy reloads (RFA-aszr) |
| Model provider catalog | Signature verification for provider catalog (RFA-l6h6.2.6) |
| Guard artifact integrity | SHA-256 digest + optional signature verification |
| Production image lock | `config/compose-production-intent.env` uses digest-pinned references |

---

## 6. Container Security

**Status: PASS (3 high findings fixed)**

### Findings Fixed

| Finding | Severity | Fix |
|---------|----------|-----|
| `Dockerfile.messaging-sim` uses distroless without `:nonroot` | HIGH | Changed to `static-debian12:nonroot@sha256:...` |
| `examples/go/Dockerfile` runs as root | HIGH | Added `adduser` + `USER app` |
| `examples/python/Dockerfile` runs as root | HIGH | Added `groupadd`/`useradd` + `USER appuser` |

### Dockerfile Best Practices Compliance

| Dockerfile | Multi-stage | Non-root | Digest-pinned | Minimal base |
|------------|:-----------:|:--------:|:-------------:|:------------:|
| Dockerfile.gateway | Yes | Yes (distroless:nonroot) | Yes | Yes (distroless) |
| Dockerfile.go-service | Yes | Yes (distroless:nonroot) | Yes | Yes (distroless) |
| Dockerfile.messaging-sim | Yes | Yes (FIXED) | Yes | Yes (distroless) |
| Dockerfile.s3-mcp-server | Yes | Yes (distroless:nonroot) | Yes | Yes (distroless) |
| Dockerfile.spike-bootstrap | Yes | Yes (upstream) | Yes | Yes (upstream distroless) |
| Dockerfile.spike-keeper | Yes | Yes (upstream) | Yes | Yes (upstream distroless) |
| Dockerfile.spike-nexus | Yes | Yes (UID 1000) | Yes | Yes (upstream distroless) |
| Dockerfile.spire-agent | Yes | No (requires root) | Yes | Yes (busybox) |
| examples/content-scanner | Yes | Yes (UID 10001) | Yes | Yes (alpine) |
| examples/go | Yes | Yes (FIXED) | No | Yes (alpine) |
| examples/mock-guard-model | Yes | Yes (UID 10001) | Yes | Yes (alpine) |
| examples/mock-mcp-server | Yes | Yes (UID 10001) | Yes | Yes (alpine) |
| examples/python | Yes | Yes (FIXED) | No | Yes (slim) |

### Accepted Risks

- **Dockerfile.spire-agent** runs as root: Required for SPIRE agent node attestation
  and Docker workload attestor (needs host PID namespace + Docker socket access).
  Documented in docker-compose.yml with explicit `privileged: true` justification.
- **examples/go and examples/python** lack digest-pinned base images: These are
  example/demo Dockerfiles, not production. Accepted risk for developer convenience.

### Compose Security

- SPIRE server runs with `privileged: true` + `pid: host` -- required for node
  attestation. Documented with clear justification.
- Gateway, SPIKE, and MCP services run with `security_opt: [no-new-privileges:true]`
  and `read_only: true` in both standard and strict compose profiles.

---

## 7. Dependency Audit

### Go Modules

**govulncheck output:** No vulnerabilities found.

**go mod verify output:** All modules verified.

**Key dependencies and their security posture:**

| Dependency | Version | Purpose | Notes |
|-----------|---------|---------|-------|
| github.com/spiffe/go-spiffe/v2 | v2.6.0 | SPIFFE/SPIRE integration | Core identity library |
| github.com/open-policy-agent/opa | v1.13.1 | Policy engine | Embedded OPA evaluation |
| github.com/gorilla/websocket | v1.5.3 | WebSocket transport | MCP SSE/WS communication |
| github.com/redis/go-redis/v9 | v9.17.3 | KeyDB client | Session/rate-limit storage |
| go.opentelemetry.io/otel | v1.40.0 | Observability | Distributed tracing |
| golang.org/x/crypto | v0.47.0 | Cryptographic primitives | Indirect dependency |
| google.golang.org/grpc | v1.78.0 | gRPC transport | OTLP export |
| gopkg.in/yaml.v3 | v3.0.1 | YAML parsing | Config/policy files |

### Python Dependencies (SDK)

| Dependency | Version | Purpose |
|-----------|---------|---------|
| httpx | >=0.28.0 | HTTP client for gateway API communication |
| opentelemetry-api | >=1.39.0 | Observability (optional) |
| python-dotenv | >=1.0.1 | Env file loading (optional) |
| pytest | >=9.0.0 | Testing (dev only) |

**Note:** Python dependencies are project-local and `uv`-managed via
`sdk/python/pyproject.toml`, `tools/compliance/pyproject.toml`,
`sample-agents/*/pyproject.toml`, and `examples/python/pyproject.toml`.

---

## 8. Automated Scan Results

### go vet

```
$ go vet ./...
(no output -- all checks pass)
```

### govulncheck

```
$ govulncheck ./...
No vulnerabilities found.
```

### go mod verify

```
$ go mod verify
all modules verified
```

---

## 9. Findings Summary

### Critical Findings

None.

### High Findings (all fixed)

| ID | Finding | Status |
|----|---------|--------|
| H-1 | Dockerfile.messaging-sim runs as root (missing :nonroot tag) | FIXED |
| H-2 | examples/go/Dockerfile runs as root | FIXED |
| H-3 | examples/python/Dockerfile runs as root | FIXED |

### Medium Findings (accepted risk)

| ID | Finding | Rationale |
|----|---------|-----------|
| M-1 | SPIRE agent requires privileged mode | Required for node attestation; documented in compose |
| M-2 | InsecureSkipVerify in SPIKE redeemer dev path | Guarded by nil x509Source (only when SPIRE unavailable); nolint annotation present |
| M-3 | DemoRugpullAdminEnabled config option | Disabled by default; requires explicit env var opt-in; demo-only feature |
| M-4 | Kubernetes PSS set to privileged for SPIRE namespace | Required for SPIRE agent host PID/docker socket access; documented |

### Low Findings (informational)

| ID | Finding | Notes |
|----|---------|-------|
| L-1 | examples/go and examples/python Dockerfiles lack digest-pinned base images | Demo containers, not production |
| L-2 | context_fetcher GetContent contentID path traversal | Fixed with input validation; IDs are UUID-generated internally |
| L-3 | Discord webhook reads DISCORD_PUBLIC_KEY from env at request time | No caching; minor performance concern, not a security issue |
| L-4 | Token generator runs as root | One-shot init container that exits after token creation |

---

## 10. Remediation Actions Taken

1. **Dockerfile.messaging-sim:** Changed base image from `gcr.io/distroless/static-debian12`
   to `gcr.io/distroless/static-debian12:nonroot` with proper digest pin.

2. **examples/go/Dockerfile:** Added non-root user (`adduser -D -u 10001 app`) and
   `USER app` directive.

3. **examples/python/Dockerfile:** Added non-root user via `groupadd`/`useradd` and
   `USER appuser` directive.

4. **internal/tools/context_fetcher.go:** Added path traversal validation to
   `GetContent()` method -- rejects contentIDs containing `/`, `\`, `..`, or empty
   strings.

---

## 11. Conclusions

The PRECINCT codebase demonstrates strong security practices:

- Zero-trust architecture with SPIFFE/SPIRE for workload identity
- Defense-in-depth with multiple middleware layers (DLP, OPA, deep scan, rate limiting)
- Proper secret management via SPIKE late-binding references
- Comprehensive audit logging with integrity verification
- Supply chain security with digest-pinned images and attestation signatures
- Container hardening with distroless bases, non-root users, and read-only filesystems

All critical and high findings have been fixed. Medium findings have documented
accepted risk rationale. The codebase is ready for open-source release from a
security perspective.
