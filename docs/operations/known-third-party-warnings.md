# Known Third-Party Container Warnings

This document catalogs log warnings from third-party components in the PRECINCT
deployment stack that may still appear in supported environments. These are
documented so operators and auditors are not surprised during security reviews.

Notes on recently removed noise:

- `GatewayClient sends X-SPIFFE-ID only for dev-mode identity...` was removed from the Python SDK for production-style clients.
- `opa policy hot-reload enabled WITHOUT attestation...` and `tool-registry hot-reload enabled WITHOUT attestation...` are no longer expected in the supported demo/runtime paths because attestation is wired by default.
- `stream close failed (fs_stream_close_failed)` is no longer expected from the supported gateway/control startup path.
- `TLS handshake error from <IP>: EOF` is no longer expected from `spike-nexus` in local K8s because the local overlay uses an mTLS-aware exec probe.

## SPIRE Server

**Warning:** `Current umask 0022 is too permissive; setting umask 0027`

- **Source:** SPIRE server process startup
- **Severity:** Informational
- **Explanation:** SPIRE detects the container's default umask (0022) and
  tightens it to 0027 for its own files. This is a defensive measure by SPIRE,
  not an error. The container's base image sets the default umask; SPIRE
  overrides it.
- **Action:** None required. SPIRE handles this automatically.

## SPIRE Agent

**Warning:** `Insecure bootstrap enabled; skipping server certificate verification`

- **Source:** SPIRE agent attestation during startup
- **Severity:** Expected in dev/demo mode
- **Explanation:** In compose/local-K8s deployments, the SPIRE agent uses
  join-token attestation without verifying the SPIRE server's certificate.
  This is standard for development. In production, the agent should use a
  trusted CA bundle or node attestation (AWS IID, K8s PSAT).
- **Action:** For production: configure `trust_bundle_path` or use a
  node attestor that validates the server certificate.

**Error:** `No identity issued (registered=false)`

- **Source:** Workload API requests during startup race
- **Severity:** Transient (resolves within seconds)
- **Explanation:** During the first few seconds after startup, the SPIRE agent
  may receive workload API requests before workload entries are registered by
  `spire-entry-registrar`. The agent correctly returns "no identity" until
  registration completes. The gateway's SPIKE client retries automatically.
- **Action:** None required. Self-resolving within 5-10 seconds.

## SPIKE Keeper

**Error (Keeper only, local K8s):** `TLS handshake error from <IP>: EOF`

- **Source:** Kubernetes liveness/readiness probes
- **Severity:** Cosmetic (K8s deployments only)
- **Explanation:** SPIKE Keeper still uses a TCP socket probe on port 8443 (its
  mTLS port). The kubelet opens a TCP connection, then closes without
  completing an mTLS exchange. Keeper logs this as a TLS error. This is a
  probe artifact, not an application failure.
- **Action:** None required. Expected K8s probe behavior.

## OpenClaw

**Warning:** `dangerous config flags enabled: dangerouslyAllowHostHeaderOriginFallback=true`

- **Source:** OpenClaw gateway startup
- **Severity:** Expected in dev/demo mode
- **Explanation:** The demo compose/K8s configuration enables host-header
  origin fallback for the OpenClaw UI. This weakens origin checks and should
  only be used in development. In production, configure proper CORS origins.
- **Action:** For production: remove `dangerouslyAllowHostHeaderOriginFallback`
  and configure explicit allowed origins.

## Tavily MCP Server (Real Mode)

**Error:** `This request exceeds this API key's set usage limit`

- **Source:** Tavily search API
- **Severity:** External API quota
- **Explanation:** The demo runs multiple search queries across two cycles.
  Free-tier Tavily API keys have low quotas. This error appears when the
  quota is exhausted mid-demo.
- **Action:** Use a Tavily API key with sufficient quota, or run only one
  demo cycle (`--cycles 1` if supported). The demo's first cycle typically
  completes within free-tier limits.

---

## PRECINCT Gateway

The PRECINCT gateway itself produces **zero warnings and zero errors** in a
correctly configured deployment. If you see gateway-level warnings, they
indicate a configuration issue:

| Warning | Cause | Fix |
|---------|-------|-----|
| `unsigned updates will be accepted` | Missing attestation keys | Set `TOOL_REGISTRY_PUBLIC_KEY` and `OPA_POLICY_PUBLIC_KEY` env vars |
| `failed to load guard model API key from SPIKE` | SPIKE Nexus unreachable at startup | Ensure spike-secret-seeder completes before gateway starts |
| `exporter export timeout` | OTel collector not running | Only set `OTEL_EXPORTER_OTLP_ENDPOINT` when Phoenix stack is active |
| `token exchange config not loaded` | Optional token-exchange endpoint disabled | Informational only. Provide `TOKEN_EXCHANGE_SIGNING_KEY` and token-exchange config only if enabling that feature |
