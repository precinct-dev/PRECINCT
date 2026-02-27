
---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### Document POC vs Production boundaries explicitly

**Priority:** Important

**Context:** Both stories in the SPIKE Nexus epic surfaced POC limitations discovered during implementation rather than documented upfront:
- Token ownership is per-request (stateless), not server-tracked
- Token expiry isn't enforced when IssuedAt=0
- Docker Compose uses InsecureSkipVerify for dev convenience

**Recommendation:** When creating POC-scoped stories:
1. **Sr. PM MUST explicitly list POC boundaries** in the story description (e.g., "POC Limitations: token ownership is per-request, not persistent")
2. ARCHITECTURE.md should have a "POC vs Production" section listing known shortcuts
3. Milestone demo scripts should note "POC limitation" when showing behavior that wouldn't be production-ready

**Applies to:** All POC-scoped epics, especially security-critical features

**Source stories:** RFA-a2y.1, RFA-a2y.2


---

## [Added from Epic RFA-hh5 retro - 2026-02-06]

### Store interfaces must document mutation semantics

**Priority:** Critical

**Context:** RFA-hh5.1 discovered that InMemoryStore and KeyDBStore have different mutation semantics due to pointer vs serialization behavior, requiring special handling in RecordAction.

**Recommendation:** When designing a store interface with both in-memory and persistence-backed implementations, explicitly document mutation semantics in the interface contract. If the interface returns pointers, clarify whether the caller can mutate them or if they receive immutable copies. Consider making all implementations return immutable copies to avoid semantic differences.

**Applies to:** All store/repository pattern implementations with multiple backends (in-memory, Redis, SQL, etc.)

**Source stories:** RFA-hh5.1

### Time-based algorithms require sub-second precision

**Priority:** Critical

**Context:** RFA-hh5.2 discovered that storing lastFill as Unix seconds caused phantom token refills due to sub-second precision loss in the token bucket algorithm.

**Recommendation:** For all time-based algorithms requiring sub-second precision (rate limiting, token buckets, timestamps for ordering), use UnixNano or equivalent high-precision timestamps. Never use Unix seconds for algorithms that execute multiple times per second.

**Applies to:** Rate limiting, token buckets, distributed locking, timestamp-based ordering.

**Source stories:** RFA-hh5.2

### Reuse key-generation functions to prevent drift

**Priority:** Important

**Context:** RFA-hh5.3 reused key-generation functions (keyDBSessionKey, rateLimitTokensKey, etc.) in GDPRDeleteAllData to ensure key patterns cannot drift between the main code and deletion code.

**Recommendation:** When implementing cleanup/deletion operations for persistence stores, ALWAYS reuse the same key-generation functions as the main code. Never duplicate key pattern logic. Extract key generation to shared utility functions if not already done.

**Applies to:** All cleanup, deletion, migration, or administrative operations on persistence stores.

**Source stories:** RFA-hh5.3

### Use Redis pipelines for bulk operations

**Priority:** Nice-to-have

**Context:** RFA-hh5.3 used Redis pipelines for batch deletion of multiple keys (sessions, actions, rate limits), providing near-atomic behavior and better performance than individual DEL commands.

**Recommendation:** For bulk operations on Redis/KeyDB (batch deletions, multi-key updates), use pipelines instead of individual commands. This reduces network round-trips and provides closer-to-atomic behavior.

**Applies to:** Bulk delete, bulk update, GDPR deletion, data migration operations on Redis/KeyDB.

**Source stories:** RFA-hh5.3

---

## [Added from Epic RFA-m6j retro - 2026-02-06]

### OTel Collector dependencies must be explicit in docker-compose

**Priority:** Important

**Context:** docker-compose.yml gateway service does not declare depends_on for otel-collector. If the collector is not ready when the gateway starts, spans may be lost during startup.

**Recommendation:** When services depend on the OTel Collector for observability, add explicit `depends_on` declarations in docker-compose.yml to ensure collector is ready before dependent services start. This prevents lost spans during startup.

**Applies to:** All docker-compose configurations with OTel Collector

**Source stories:** RFA-m6j.1 (spawned bug RFA-39h)


---

## [Added from Epic RFA-8z8 retro - 2026-02-06]

### go-spiffe v2 SDK is production-ready for SPIRE integration

**Priority:** Important

**Context:** Both stories leveraged go-spiffe v2 SDK's high-level APIs with no issues. The SDK handled X.509 Source creation, TLS config generation, and Workload API communication cleanly. No low-level certificate management was needed.

**Recommendation:** For all SPIRE integrations in Go services:
1. Use workloadapi.NewX509Source() for obtaining SVIDs (don't manually fetch from Workload API)
2. Use tlsconfig.TLSServerConfig() for servers accepting mTLS
3. Use tlsconfig.MTLSClientConfig() + AuthorizeAny() for clients connecting to SPIRE-protected services
4. Let go-spiffe handle certificate rotation automatically (no manual refresh logic needed)

**Applies to:** All Go services integrating with SPIRE for mTLS

**Source stories:** RFA-8z8.1, RFA-8z8.2

### SVID-to-PEM init container pattern for non-Workload-API services

**Priority:** Important

**Context:** KeyDB cannot speak the SPIRE Workload API directly. The pattern of using an init container (or sidecar) to fetch SVID and write PEM files to a shared volume is the correct approach for services that need TLS but can't use the Workload API.

**Recommendation:** For services that need SPIRE-issued certificates but can't use the Workload API:
1. Use a small init container (or sidecar) that runs `spire-agent api fetch x509` and writes PEM files
2. Mount a shared volume between init container and target service
3. Configure target service with standard TLS cert/key/CA paths
4. Document this as an explicit architectural pattern (not a workaround)
5. Consider: a lighter-weight SVID-fetch tool instead of the full spire-agent image

**Applies to:** All non-Go services or services without Workload API support needing SPIRE certificates

**Source stories:** RFA-8z8.2

---

## [Added from Epic RFA-8jl retro - 2026-02-06]

### GDPR Article 30 ROPA has exactly 7 mandatory categories

**Priority:** Important

**Context:** GDPR Article 30(1) requires exactly 7 categories in ROPA: controller/processor ID, data subject categories, processing categories, purposes, retention periods, technical measures (Art. 32 cross-ref), and third-country transfers. The list is exhaustive in the regulation text.

**Recommendation:** When implementing compliance documentation, work from the regulation text directly, not summaries. For GDPR Art. 30, the 7 categories are non-negotiable and exhaustive.

**Applies to:** All compliance documentation stories, especially GDPR-related

**Source stories:** RFA-w4m

### SPIFFE IDs are pseudonymous identifiers under GDPR

**Priority:** Important

**Context:** SPIFFE IDs are pseudonymous identifiers under GDPR Recital 26 -- not directly personal data, but subject to GDPR if the controller can link them to natural persons.

**Recommendation:** For privacy impact assessments, classify SPIFFE IDs (and similar machine identifiers) as pseudonymous data, not non-personal data. Document this classification in the ROPA.

**Applies to:** All privacy/GDPR stories involving machine identifiers

**Source stories:** RFA-w4m


---

## [Added from Epic RFA-7bh retro - 2026-02-06]

### SPIRE agent requires privileged PodSecurity Standard

**Priority:** Important

**Context:** SPIRE agent DaemonSet uses hostPID: true and hostNetwork: true for node-level identity attestation. This conflicts with "restricted" PodSecurity Standard and requires the spire-system namespace to use "privileged" PSS.

**Recommendation:** When deploying SPIRE to K8s, always set the spire-system namespace to "privileged" PSS. Document this as a known security boundary, not a workaround. SPIRE agent inherently requires privileged access for attestation.

**Applies to:** All K8s deployments with SPIRE agent

**Source stories:** RFA-7bh.1

### Docker Desktop kubeadm does not support k8s_psat attestation

**Priority:** Important

**Context:** Docker Desktop lacks an OIDC provider, so k8s_psat (Projected Service Account Token) attestation doesn't work. join_token is the correct alternative for local development SPIRE.

**Recommendation:** Use join_token attestation for local K8s dev environments. Reserve k8s_psat for managed K8s clusters (EKS, GKE) that have OIDC providers configured. Document attestation strategy per environment in ARCHITECTURE.md.

**Applies to:** Local K8s development environments with SPIRE

**Source stories:** RFA-7bh.1

### IaC validation via kustomize build + kubeconform is appropriate for K8s manifest stories

**Priority:** Important

**Context:** Both RFA-7bh stories were accepted using offline validation (kustomize build + kubeconform) without requiring a live cluster. This established a clear precedent consistent with EKS IaC stories.

**Recommendation:** For K8s Infrastructure-as-Code stories, kustomize build + kubeconform is the appropriate validation tier. Manifest correctness is deterministic. Reserve live cluster testing for E2E integration stories.

**Applies to:** All K8s IaC stories (overlays, admission webhooks, resource manifests)

**Source stories:** RFA-7bh.1, RFA-7bh.2

### sigstore/policy-controller and OPA Gatekeeper coexist independently

**Priority:** Nice-to-have

**Context:** RFA-7bh.2 deployed both admission webhooks. K8s API server calls them in parallel with no ordering dependency. They use different namespace targeting: sigstore uses opt-in (policy.sigstore.dev/include=true), Gatekeeper uses opt-out (config exclusion list).

**Recommendation:** When running multiple admission webhooks, document their namespace targeting strategies and ensure they don't conflict. Both must return "allow" for admission to succeed.

**Applies to:** K8s clusters with multiple admission controllers

**Source stories:** RFA-7bh.2


---

## [Added from Epic RFA-xynt retro - 2026-02-26]

### Per-message SPIKE resolution is architecturally distinct from upgrade-time token substitution

**Priority:** Critical

**Context:** The HTTP middleware chain (step 13: token substitution) runs ONCE on the WS upgrade request. Per-message credentials in WS frame params (auth_ref field) must be resolved by the adapter directly via resolveSPIKERef(), not by the middleware chain. RFA-1fui's first delivery passed auth_ref verbatim as the Bearer token header without calling the redeemer, which would have sent a raw spike:// URI to external messaging APIs.

**Recommendation:**
1. In all future WS handler stories, document explicitly: "Per-message SPIKE resolution happens in the adapter via resolveSPIKERef(), NOT via middleware token substitution."
2. Any WS frame carrying credentials via auth_ref MUST route those credentials through resolveSPIKERef() before they reach external API calls.
3. Integration tests for per-message SPIKE resolution must verify the resolved value (e.g., "secret-value-for-whatsapp-api-key") rather than just that the request succeeded.
4. PM-Acceptor checklist for WS stories with auth_ref: "Verify the redeemer is called, not auth_ref passed verbatim."

**Applies to:** All WS handler stories involving per-message credentials or SPIKE references

**Source stories:** RFA-1fui (rejected once), RFA-mbmr, RFA-ajf6

---

### Internal loopback is the correct pattern for inbound paths requiring full middleware traversal

**Priority:** Important

**Context:** The webhook receiver (RFA-cweb) must ensure inbound webhook payloads traverse all 13 middleware steps (DLP, rate limiting, audit, etc.). The correct implementation is an internal HTTP POST to the gateway's own /v1/ingress/submit endpoint. Building a PlaneRequestV2 and calling evaluation directly bypasses DLP, rate limiting, and audit entirely.

**Recommendation:**
1. Document internal loopback as an explicit architectural pattern: any new inbound data path that must traverse the full middleware chain should POST to /v1/ingress/submit internally, not call evaluation functions directly.
2. The loopback HTTP client requires InsecureSkipVerify for self-signed TLS in POC mode. Document this as a POC limitation with a note about production certificate trust.
3. Two-layer defense is the correct design: (1) webhook handler checks connector conformance as a fast-path reject; (2) loopback POST traverses the full middleware chain including a second connector check in handleIngressAdmit.
4. Integration tests for webhook stories must verify middleware chain traversal explicitly (e.g., audit log entries for /v1/ingress/submit path), not just that the endpoint returns 200.

**Applies to:** All stories adding new inbound data paths to the gateway that must be policy-mediated

**Source stories:** RFA-cweb, RFA-yt63

---

### Attestation artifact re-signing must be automated and documented

**Priority:** Important

**Context:** config/tool-registry.yaml changes invalidate the Ed25519 .sig attestation files for tool-registry, model-provider-catalog, and guard-artifact. This caused two pre-existing test failures traced to an undocumented key change (RFA-exak). The re-signing sequence is known but not automated. Any developer who touches tool-registry.yaml will encounter cryptic test failures before discovering the root cause.

**Recommendation:**
1. Create a Makefile target (e.g., make attestation-resign) that runs the full re-signing sequence for all three artifacts.
2. Add a comment header to config/tool-registry.yaml: "Modifying this file requires running make attestation-resign to update signature files."
3. Document the rotation procedure in ATTESTATION_ROTATION.md: which artifacts, which command, keypair format, and storage location.
4. CI should run tests/integration after any change to config/*.yaml to catch key mismatches immediately.

**Applies to:** All stories modifying config/tool-registry.yaml, config/opa/tool_registry.yaml, or any attested configuration artifact

**Source stories:** RFA-1fui, RFA-np7t, RFA-exak (P3 issue)
