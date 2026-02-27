
---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### Dependency injection for external services is mandatory

**Priority:** Critical

**Context:** Testing SPIKENexusRedeemer without requiring a running SPIKE Nexus required a constructor accepting an HTTP client (`NewSPIKENexusRedeemerWithClient()`). This enabled clean unit tests with httptest.Server mocks while keeping production code unchanged.

**Recommendation:** For all future external service integrations (APIs, databases, message queues):
1. **Always provide a constructor accepting the client/connection** (e.g., `NewFooClientWithHTTPClient(httpClient)`)
2. Provide a convenience constructor for production use that creates the default client
3. Unit tests MUST use the injectable constructor with mocks
4. Integration tests use the convenience constructor with real infrastructure

**Applies to:** All stories creating clients for external APIs, databases, or services

**Source stories:** RFA-a2y.1

---

### E2E scripts should produce stakeholder-ready summaries

**Priority:** Important

**Context:** The SPIKE Nexus E2E script included a summary section that directly showed "architecture claim → evidence" in demo-ready format. This made the milestone immediately demoable without additional preparation.

**Recommendation:** For all milestone E2E scripts:
1. **Include a summary section** that outputs stakeholder-friendly proof (not just pass/fail)
2. Format: "Architecture Claim: [X] → Evidence: [test output showing X]"
3. Use clear, non-technical language in the summary (avoid implementation details)
4. Summary should be copy-pasteable into demo decks or stakeholder reports

**Applies to:** All milestone E2E validation stories

**Source stories:** RFA-a2y.2


---

## [Added from Epic RFA-pkm retro - 2026-02-06]

### Test Data Must Match Production Constraints

**Priority:** Important

**Context:** Auditor constructor tests initially failed because the Auditor requires real file paths for digest computation. Tests using relative paths to `config/` directory failed; tests creating temp files passed. The production component has filesystem constraints that tests must respect.

**Recommendation:** When testing components that interact with the filesystem or external resources:
1. **Match production constraints in tests** - If a component requires file paths, tests must provide valid file paths (not mocked or relative paths that don't exist)
2. **Use temp files/directories** for test isolation instead of relative paths that may not exist
3. **Explicitly document filesystem/resource requirements** in test setup comments (e.g., "// Auditor requires real file paths for digest computation")
4. **Fail fast with clear messages** if test prerequisites aren't met

**Applies to:** All stories involving file I/O, configuration loading, certificate handling, logging, audit trails, any component that computes checksums or digests

**Source stories:** RFA-pkm.1

### Integration Tests with Real APIs in Walking Skeletons

**Priority:** Critical

**Context:** RFA-pkm.1's real Groq API integration tests caught the response format discrepancy (numeric scores vs class labels) that documentation didn't mention. Without these tests, the issue wouldn't have been discovered until production.

**Recommendation:** For all walking skeleton stories that integrate external APIs:
1. **Include real API integration tests** - Not just mocked unit tests, but actual API calls with real credentials
2. **Test multiple scenarios** - Success cases, error cases, edge cases (rate limits, timeouts, malformed responses)
3. **Run integration tests in CI** - Use environment variables for API keys, fail the build if integration tests fail
4. **Document API behavior divergence** - When actual behavior differs from documentation, capture this in code comments and test assertions

**Applies to:** All walking skeleton stories, all stories involving third-party API integration

**Source stories:** RFA-pkm.1


---

## [Added from Epic RFA-hh5 retro - 2026-02-06]

### Use miniredis FastForward for TTL testing

**Priority:** Important

**Context:** miniredis (alicebob/miniredis/v2) was used in RFA-hh5.1 for TTL testing with FastForward capability, eliminating the need for real time delays in tests.

**Recommendation:** For all future Redis/KeyDB integration tests requiring TTL verification, use miniredis with FastForward instead of real time.Sleep() calls. This makes tests faster and more reliable.

**Applies to:** All Redis/KeyDB-related stories, particularly those testing TTL, expiration, or time-based cleanup.

**Source stories:** RFA-hh5.1

### Refactoring must update ALL artifacts in same commit

**Priority:** Critical

**Context:** RFA-hh5.3 observed 6 pre-existing test failures where middleware was refactored to use WriteGatewayError but tests still expected the old http.Error JSON format.

**Recommendation:** When refactoring error handling or response formats, update ALL artifacts in the same commit: production code, tests, AND documentation. Include "make test" as a mandatory gate before marking delivered.

**Applies to:** All refactoring stories, particularly those changing API contracts or response formats.

**Source stories:** RFA-hh5.3 (observed), RFA-m6j.2 (root cause)

### Persistence operations require full lifecycle integration tests

**Priority:** Important

**Context:** RFA-hh5.3's GDPR deletion tests verified full lifecycle (create, delete, verify) with real KeyDB (no mocks), providing strong confidence in the implementation.

**Recommendation:** For all data persistence operations (especially security-sensitive like GDPR deletion), integration tests MUST use real backends and verify full lifecycle: create data, perform operation, verify expected state. No mocks.

**Applies to:** All persistence stories, compliance stories, data deletion/cleanup stories.

**Source stories:** RFA-hh5.3


---

## [Added from Epic RFA-8z8 retro - 2026-02-06]

### Integration tests for TLS must use real handshakes, not mocks

**Priority:** Critical

**Context:** Both stories in RFA-8z8 proved that integration tests with real TLS handshakes (no mocks) catch real security issues. miniredis doesn't support TLS, requiring a TLS proxy pattern to test Redis/KeyDB TLS. The TLS proxy pattern is now proven in this codebase.

**Recommendation:** For all future TLS/mTLS integration tests:
1. Use real TLS handshakes via go-spiffe SDK or standard crypto/tls
2. For services with non-TLS-aware mocks (like miniredis), use the TLS listener → plaintext proxy → mock pattern established in keydb_tls_test.go
3. Verify negative cases: untrusted certs, plain HTTP rejection, missing client certs
4. Never mock tls.Config or skip TLS verification with InsecureSkipVerify in tests

**Applies to:** All stories involving TLS, mTLS, certificate validation, or SPIRE integration

**Source stories:** RFA-8z8.1, RFA-8z8.2

---

## [Added from Epic RFA-m6j retro - 2026-02-06]

### Use resource.NewSchemaless() to avoid OTel semconv version conflicts

**Priority:** Important

**Context:** OTel SDK semconv v1.24.0 conflicts with SDK v1.40.0 due to schema URL mismatch when creating resources with both resource.Default() and semantic convention attributes.

**Recommendation:** When instrumenting with OpenTelemetry in Go, use `resource.NewSchemaless()` instead of `resource.New()` when combining resource.Default() with custom attributes. This avoids schema URL conflicts between different versions of semconv packages.

**Applies to:** All OTel instrumentation stories

**Source stories:** RFA-m6j.1

### OTel exporters use lazy connection - design tests accordingly

**Priority:** Nice-to-have

**Context:** The OTel gRPC exporter uses lazy connection and doesn't fail at creation time even if the endpoint is unreachable.

**Recommendation:** When testing OTel instrumentation, design tests for async connection behavior. Don't expect immediate failures if the collector is unreachable. Use in-memory span exporters (tracetest.InMemoryExporter with sdktrace.WithSyncer()) for deterministic tests.

**Applies to:** All OTel integration tests

**Source stories:** RFA-m6j.1

### Package-level OTel tracers must be reassigned in tests

**Priority:** Important

**Context:** Package-level tracer variables must be reassigned in tests to pick up the test TracerProvider.

**Recommendation:** When testing code that uses package-level OTel tracer variables, explicitly reassign the tracer in test setup: `tracer = tp.Tracer("service-name")`. Without this, tests will use the global tracer instead of the test TracerProvider.

**Applies to:** All OTel unit tests using package-level tracers

**Source stories:** RFA-m6j.1

### Reuse mock implementations from sibling test files

**Priority:** Nice-to-have

**Context:** mockHandleStore and mockGuardClient from sibling test files were reusable in the same package without duplication.

**Recommendation:** Before creating mock implementations in test files, check if sibling test files in the same package already define equivalent mocks. Reuse them to reduce duplication.

**Applies to:** All test stories

**Source stories:** RFA-m6j.2


---

## [Added from Epic RFA-xynt retro - 2026-02-26]

### t.Logf is not an assertion -- tests using only t.Logf always pass

**Priority:** Critical

**Context:** RFA-yt63 (integration tests for WS messaging pipeline) was rejected 3 consecutive times. In each attempt the developer used t.Logf where t.Errorf or t.Fatalf was required. t.Logf appends to the log buffer and does NOT mark the test as failed. A test body with only t.Logf passes unconditionally regardless of whether the asserted condition is true. This affected audit log verification (Test 8) and OPA policy verification (Test 4).

**Recommendation:**
1. For any test covering security-critical assertions (audit log present, connector rejected, OPA decision exists), PM-Acceptor must verify: "Does this test actually FAIL when the condition is not met?"
2. Developer agents must understand: t.Logf = diagnostics only. t.Errorf = non-fatal assertion failure. t.Fatalf = fatal assertion failure (stops the test immediately). A test with no t.Error/t.Fatal call cannot fail.
3. When the assertion is "check that X is present in a log/response", the negative path (X is absent) must call t.Errorf or t.Fatalf, not t.Logf with a warning message.
4. A lint check (or code review gate) can flag test functions with no t.Error/t.Fatal/require.*/assert.* calls.

**Applies to:** All integration and unit test stories, especially those asserting audit logs, policy engine responses, or external service interactions

**Source stories:** RFA-yt63 (rejected 3 times before acceptance on 4th attempt)

---

### HTTP mux routing must be tested at the mux level, not via direct handler calls

**Priority:** Important

**Context:** RFA-ncf1 extended the messaging simulator with a Telegram endpoint registered at "/bot" in Go 1.22+ ServeMux. The actual Telegram path format is "/botMYTOKEN/sendMessage", which "/bot" does NOT match (Go 1.22 ServeMux requires trailing '/' for prefix matching). All 10 unit tests passed because they called the handler function directly, bypassing the mux entirely. The live HTTP server returned 404 for every real Telegram request.

**Recommendation:**
1. For any HTTP server using path-based routing, include at least one test that exercises the REAL mux via httptest.NewServer with the actual mux registration, not direct handler calls.
2. Go 1.22+ ServeMux behavior: "/foo" matches ONLY the exact path "/foo". "/foo/" matches "/foo/" and all paths with that prefix. A path like "/bot<token>/sendMessage" cannot be expressed as a clean ServeMux pattern and requires a catch-all dispatcher.
3. The mux-level regression test (httptest.NewServer + real mux + real HTTP request) should be mandatory whenever a new HTTP path is registered, especially with dynamic path segments.

**Applies to:** All stories registering new HTTP routes with dynamic path segments or non-standard URL patterns

**Source stories:** RFA-ncf1 (rejected once for routing bug invisible to direct handler tests)

---

### Service readiness patterns are mandatory for integration tests against Docker Compose

**Priority:** Important

**Context:** RFA-yt63's first delivery contained no service readiness patterns. Tests failed with connection refused on a cold Compose startup with no diagnostic information. The fix required adding waitForGatewayWS and waitForService helpers with exponential backoff.

**Recommendation:**
1. Integration tests MUST include a TestMain or per-test setup that polls service health endpoints before running assertions.
2. Minimum readiness set for a standard Compose stack test: gateway WS endpoint, any external simulator health endpoints, gateway HTTPS health.
3. The retry pattern should use exponential backoff (not fixed sleep) with a configurable timeout (60-120 seconds for cold Compose startup).
4. If a service is not ready within the timeout, the test must fail with a clear diagnostic: "Service X not ready after Y seconds -- is the Compose stack running?"
5. A simHealthURL or equivalent constant declared but never used is a gap -- service readiness checks must actually be called.

**Applies to:** All integration test stories that run against Docker Compose stacks

**Source stories:** RFA-yt63 (rejected for missing readiness patterns)

---

### Integration tests and E2E scripts have distinct non-interchangeable roles

**Priority:** Important

**Context:** RFA-xzj6 (E2E scenarios) must NOT call go test -tags=integration. It must use external tools (curl, CLI binaries) as an operator would. RFA-yt63 (integration tests) covers detailed behavioral assertions in Go test functions. The boundary is clear: integration tests = Go test functions, no mocks, build-tagged, assert detailed behavior. E2E scripts = bash + external tools, assert the system works from the outside.

**Recommendation:**
1. Integration tests: Go test functions with //go:build integration tag, no mocks, run via go test -tags=integration, assert detailed behavioral properties (audit log entries, policy engine responses, middleware chain traversal).
2. E2E scripts: bash scripts using curl, compiled CLI tools, jq; verify system from the outside; exit non-zero on failure; must NOT wrap go test invocations.
3. PM-Acceptor should reject any E2E script that contains go test invocations -- that is integration test scope, not E2E scope.
4. WS-capable E2E clients must be standalone CLI binaries (package main, exit 0/1 on ok field), not Go test wrappers.

**Applies to:** All milestone E2E stories and integration test stories

**Source stories:** RFA-xzj6, RFA-yt63
