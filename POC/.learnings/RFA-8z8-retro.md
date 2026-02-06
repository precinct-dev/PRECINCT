# Retrospective: Epic RFA-8z8 - mTLS Enforcement -- SPIRE SVID-Based Encrypted Communications

**Date:** 2026-02-06
**Stories completed:** 2
**Duration:** ~4.5 hours (10:23 AM - 2:46 PM)

## Summary

This epic implemented end-to-end mTLS encryption for all inter-service communication using SPIRE-issued X.509 SVIDs. The implementation provides a dual-mode operation (SPIFFE_MODE=dev/prod) allowing teams to run the POC with simple HTTP during evaluation while enforcing compliance-grade encryption in production deployments. All 8 epic-level acceptance criteria were met with comprehensive integration testing and no mocked TLS handshakes.

**Key achievements:**
- Gateway serves HTTPS with SPIRE-issued SVID and validates client certificates
- All service-to-service communication (Gateway↔MCP, Gateway↔KeyDB, Gateway↔SPIKE Nexus) uses mTLS
- KeyDB secured via TLS using SPIRE SVID written to disk by init container
- Development mode preserved for fast iteration without TLS overhead
- Automatic certificate rotation via SPIRE Agent (1-hour default)
- OTel Collector documented as the ONE explicit exception (telemetry data only)

## Raw Learnings Extracted

### From RFA-8z8.1 (Walking Skeleton: Gateway HTTPS via SPIRE SVID)

**LEARNINGS:** (none explicitly captured - story focused on implementation)

**Observations from delivery:**
- Integration tests created with NO mocks: ValidMTLSClient, PlainHTTPSRejected, UntrustedCertRejected
- Real TLS handshakes verified in integration tests, not stubbed
- go-spiffe v2 SDK handled SPIRE Workload API complexity cleanly
- Dev mode preservation validated existing Phase 1 behavior untouched

### From RFA-8z8.2 (KeyDB and remaining inter-service mTLS)

**LEARNINGS:**
1. **Gateway.go changes can be accidentally bundled into concurrent developer agent commits when sessions overlap.** Always verify git diff before assuming your changes need committing.

2. **miniredis does not support TLS natively.** The TLS proxy pattern (TLS listener → plaintext proxy → miniredis) is the canonical way to test Redis TLS in Go.

3. **go-spiffe's tlsconfig.MTLSClientConfig + AuthorizeAny() is the simplest way** to create mTLS configs for services that accept any valid SVID from the trust domain.

4. **KeyDB (unlike Redis) is BSD-3-Clause licensed** but otherwise protocol-compatible. TLS configuration is identical to Redis TLS.

**OBSERVATIONS (unrelated to this task):**
- The keydb-svid-init container uses the spire-agent:1.10.0 image which includes the spire-agent CLI for SVID fetching. A lighter-weight SVID fetch tool could reduce image size.

## Patterns Identified

### Pattern 1: TLS Proxy for Testing Non-TLS-Aware Mocks (seen in 1 story)
miniredis (the standard in-memory Redis for Go tests) doesn't support TLS. The pattern of creating a TLS listener that proxies to the plaintext mock is the canonical solution. This pattern likely applies to any mock that doesn't natively support TLS.

### Pattern 2: go-spiffe SDK Simplifies SPIRE Integration (seen in 2 stories)
Both stories leveraged go-spiffe v2's high-level APIs (workloadapi.NewX509Source, tlsconfig.TLSServerConfig, tlsconfig.MTLSClientConfig) to handle SPIRE Workload API complexity. No low-level certificate management was needed. The SDK proved reliable and well-designed.

### Pattern 3: Dual-Mode (dev/prod) Enables Fast Iteration (architectural pattern)
SPIFFE_MODE=dev preserves all Phase 1 HTTP behavior for quick evaluation, while SPIFFE_MODE=prod enforces compliance-grade mTLS. This dual-mode approach was validated in both stories and allows teams to run POC without TLS setup overhead during initial exploration.

### Pattern 4: Filesystem-Based Certs for Non-Workload-API Services (seen in 1 story)
KeyDB cannot speak the SPIRE Workload API directly. The SVID-to-PEM init container pattern (fetch SVID, write to shared volume, configure KeyDB with PEM paths) is the correct approach for services that need TLS but can't use the Workload API. This is an acceptable architectural compromise documented in ADR-003.

### Pattern 5: Integration Tests Without Mocks Catch Real Issues (seen in 2 stories)
Both stories implemented integration tests with REAL TLS handshakes, no mocks. RFA-8z8.1 verified client cert rejection, untrusted certs, and plain HTTP rejection. RFA-8z8.2 verified KeyDB TLS connections with ping/set/get operations. No mocked TLS means real security properties are tested.

## Actionable Insights

### [TESTING] Integration tests for TLS must use real handshakes, not mocks

**Priority:** Critical

**Context:** Both stories in this epic proved that integration tests with real TLS handshakes (no mocks) catch real security issues. miniredis doesn't support TLS, requiring a TLS proxy pattern to test Redis/KeyDB TLS. The TLS proxy pattern is now proven in this codebase.

**Recommendation:** For all future TLS/mTLS integration tests:
1. Use real TLS handshakes via go-spiffe SDK or standard crypto/tls
2. For services with non-TLS-aware mocks (like miniredis), use the TLS listener → plaintext proxy → mock pattern established in keydb_tls_test.go
3. Verify negative cases: untrusted certs, plain HTTP rejection, missing client certs
4. Never mock tls.Config or skip TLS verification with InsecureSkipVerify in tests

**Applies to:** All stories involving TLS, mTLS, certificate validation, or SPIRE integration

**Source stories:** RFA-8z8.1, RFA-8z8.2

---

### [ARCHITECTURE] go-spiffe v2 SDK is production-ready for SPIRE integration

**Priority:** Important

**Context:** Both stories leveraged go-spiffe v2 SDK's high-level APIs with no issues. The SDK handled X.509 Source creation, TLS config generation, and Workload API communication cleanly. No low-level certificate management was needed.

**Recommendation:** For all SPIRE integrations in Go services:
1. Use workloadapi.NewX509Source() for obtaining SVIDs (don't manually fetch from Workload API)
2. Use tlsconfig.TLSServerConfig() for servers accepting mTLS
3. Use tlsconfig.MTLSClientConfig() + AuthorizeAny() for clients connecting to SPIRE-protected services
4. Let go-spiffe handle certificate rotation automatically (no manual refresh logic needed)

**Applies to:** All Go services integrating with SPIRE for mTLS

**Source stories:** RFA-8z8.1, RFA-8z8.2

---

### [PROCESS] Verify git diff before committing to avoid bundling unrelated changes

**Priority:** Important

**Context:** RFA-8z8.2 discovered that gateway.go changes had been committed in a prior session, causing confusion about what needed committing. When developer agents run concurrently or sessions overlap, changes can be accidentally bundled.

**Recommendation:** Developer agents should ALWAYS run `git diff` before committing to verify:
1. Only the current story's changes are staged
2. No unrelated changes from concurrent agents are included
3. If unexpected changes appear, investigate (don't blindly commit)
4. If changes belong to another story, coordinate or alert orchestrator

**Applies to:** All stories when multiple developer agents are active or sessions overlap

**Source stories:** RFA-8z8.2

---

### [ARCHITECTURE] SVID-to-PEM init container pattern for non-Workload-API services

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

### [TOOLING] TLS proxy pattern for testing services with non-TLS-aware mocks

**Priority:** Nice-to-have

**Context:** miniredis (the standard in-memory Redis mock for Go) doesn't support TLS. The pattern of creating a TLS listener that proxies to the plaintext mock was proven in keydb_tls_test.go. This pattern generalizes to any mock that lacks TLS support.

**Recommendation:** For testing TLS connections when the mock doesn't support TLS:
1. Create a net.Listener with tls.Config (real TLS handshake)
2. Accept connections, proxy bytes to/from the non-TLS mock
3. This allows real TLS handshake testing without needing a TLS-capable mock
4. Document this pattern in testing guidelines for future reference

**Applies to:** Stories testing TLS connections where no TLS-capable mock exists

**Source stories:** RFA-8z8.2

## Recommendations for Backlog

No backlog updates needed. All epic ACs were met and no follow-up stories are required.

**Potential future consideration (not blocking):**
- Evaluate lighter-weight SVID-fetch tools for init containers instead of full spire-agent:1.10.0 image (reduces container image size)

## Metrics

- **Stories accepted first try:** 2/2 (100%)
- **Stories rejected at least once:** 0
- **Most common rejection reason:** N/A
- **Test gap learnings captured:** 0 (testing was comprehensive from the start)
- **Integration test coverage:** Both stories included mandatory integration tests with real TLS handshakes, no mocks

## Key Strengths

1. **Exemplary integration testing:** Both stories included comprehensive integration tests with real TLS handshakes, no mocks. Negative cases (untrusted certs, plain HTTP rejection) were tested.

2. **Clear architectural constraints:** ADR-003 provided clear guidance on SPIRE as sole CA, no cert-manager, and OTel Collector exception. This prevented scope creep and confusion.

3. **Dual-mode design:** SPIFFE_MODE=dev/prod allows fast iteration without TLS overhead during evaluation while enforcing compliance in production.

4. **go-spiffe SDK adoption:** Leveraging the go-spiffe v2 SDK instead of low-level Workload API calls simplified implementation and improved maintainability.

5. **Detailed delivery notes:** Both stories included comprehensive delivery notes with AC verification tables, wiring details, and test output. This made PM acceptance efficient.

## Notable Observations

- **KeyDB vs Redis licensing:** KeyDB is BSD-3-Clause licensed (Redis changed to SSPL), making it a better choice for this POC. TLS configuration is identical.

- **OTel Collector exception:** The deliberate decision to NOT require mTLS for OTel Collector (telemetry data only, no secrets) was documented and validated. This is an important architectural decision that prevents over-engineering.

- **No certificate rotation logic needed:** SPIRE Agent handles automatic SVID rotation (1-hour default). Services using go-spiffe SDK automatically pick up renewed certificates with no manual refresh logic.

- **SPIFFE_MODE environment variable:** This simple config switch enables dual-mode operation. Consider this pattern for other compliance-related features that need dev/prod modes.
