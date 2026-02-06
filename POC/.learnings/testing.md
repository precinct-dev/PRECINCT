
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
