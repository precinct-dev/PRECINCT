# Retrospective: Epic RFA-pkm - Deep Scan & Guard Model -- Groq E2E with Configurable Fallback

**Date:** 2026-02-06
**Stories completed:** 2
**Duration:** Milestone epic (P0 priority)
**Epic Type:** Walking skeleton + feature extension

## Summary

This milestone epic proved Groq-based prompt guard integration with chunking for large payloads. RFA-pkm.1 established the walking skeleton with real Groq API integration and configurable fallback behavior (fail_closed vs fail_open). RFA-pkm.2 extended this with payload chunking for content exceeding the 512-token context window, using parallel API calls with bounded concurrency and max-score aggregation across chunks.

Both stories were accepted on first delivery. The epic demonstrates strong architectural clarity, comprehensive test coverage, and thorough AC verification.

## Raw Learnings Extracted

### From RFA-pkm.1 (Walking Skeleton: Groq Prompt Guard 2 integration)

- Groq Prompt Guard 2 86M via chat completions API returns numeric scores like "0.9996" as text content, not class labels like the HuggingFace model docs suggest. The parsePromptGuardContent function handles both formats for robustness.
- Scores are very decisive: injection payloads get >0.99, benign gets <0.001. AC2 threshold of 0.3 is easily met.
- Groq API latency is excellent: 80-320ms per call, well within the 5s timeout.
- The Auditor constructor requires real file paths for digest computation. Tests must create temp files, not use relative paths to config/.

**Observations (unrelated):**
- spike_redeemer.go was an untracked file with compile errors (multiple-value context). Fixed as part of this commit to unblock the build.
- TestDeepScanMiddlewareIntegration in tests/integration/ requires a running gateway server (Docker). It will always skip/fail in non-Docker environments.

### From RFA-pkm.2 (Prompt chunking for large payloads)

- Go untyped float constants (like tokensPerWord=1.3) can cause vet errors when used in constant expressions with int() conversion. Solution: assign to a variable first to force runtime evaluation.
- The chunking boundary math (words to tokens, overlap computation) requires careful handling. Using floor division for maxWords and overlapWords ensures we never exceed the token limit.
- Concurrent API call tracking for bounded concurrency test: use sync.Mutex-guarded counter + peak tracking with short sleep to ensure overlap.

**Observations (unrelated):**
- fmt.Printf in ResultProcessor (deep_scan.go:644) is a pre-existing debug artifact from RFA-pkm.1 that should be replaced with proper structured logging.

## Patterns Identified

1. **API Response Format Discrepancies** - External API documentation (HuggingFace) didn't match actual behavior (Groq). Defensive parsing that handles multiple response formats prevents fragile integrations. (seen in 1 story but likely recurring pattern with any third-party API integration)

2. **Go Constant Expression Limitations** - Untyped float constants in expressions involving type conversions can trigger vet errors. This is a Go language quirk that affects numeric computation code. (seen in 1 story)

3. **Test Environment Constraints** - Integration tests requiring Docker/external services will skip in non-Docker environments. This creates gaps in local CI validation. (observed in RFA-pkm.1)

4. **Test Data Realism** - Auditor tests require real file paths for digest computation; mocked/relative paths cause test failures. Tests must match production constraints. (seen in 1 story)

5. **Unfinished Work Cleanup** - Debug artifacts (fmt.Printf) from previous stories linger and accumulate. Needs systematic cleanup pass. (observed across both stories)

## Actionable Insights

### Integration with External APIs

**Priority:** Critical

**Context:** RFA-pkm.1 discovered that Groq Prompt Guard 2's actual API response format (numeric scores as text) differed from HuggingFace documentation (class labels). The parsePromptGuardContent function was made robust to handle both formats.

**Recommendation:** When integrating any external API (especially ML models via proxy services like Groq, Replicate, OpenRouter):
1. ALWAYS test with the real API early (in the walking skeleton)
2. Implement defensive parsing that handles multiple response formats
3. Add integration tests with real API calls to catch format drift
4. Document the actual observed format in code comments, not just the vendor docs

**Applies to:** All stories involving third-party API integration (ML models, authentication services, payment gateways, etc.)

**Source stories:** RFA-pkm.1

### Go Numeric Constant Handling

**Priority:** Important

**Context:** RFA-pkm.2 encountered vet errors when using untyped float constants (tokensPerWord=1.3) in expressions with int() conversion. This is a Go language constraint.

**Recommendation:** When writing Go code with numeric conversions involving floating-point constants:
1. Assign constants to variables before using them in type conversion expressions
2. Use explicit type declarations for numeric constants (e.g., `const tokensPerWord float64 = 1.3`)
3. Prefer runtime evaluation over constant expressions for mixed-type math

**Applies to:** All Go stories involving numeric computation, especially token counting, rate limiting, resource allocation

**Source stories:** RFA-pkm.2

### Test Data Realism

**Priority:** Important

**Context:** RFA-pkm.1 tests initially failed because Auditor constructor requires real file paths for digest computation. Tests using relative paths to config/ failed; tests creating temp files passed.

**Recommendation:** When testing components that interact with the filesystem or external resources:
1. Match production constraints in tests (e.g., if Auditor needs file paths, tests must provide valid file paths)
2. Use temp files/directories for test isolation, not relative paths
3. Explicitly document filesystem/resource requirements in test setup comments

**Applies to:** All stories involving file I/O, configuration loading, certificate handling, logging

**Source stories:** RFA-pkm.1

## Recommendations for Backlog

**Clean up debug artifacts:** The fmt.Printf in ResultProcessor (deep_scan.go:644) should be replaced with structured logging. Consider a backlog grooming story to audit for debug artifacts across the codebase.

**Integration test gaps:** TestDeepScanMiddlewareIntegration requires Docker but skips in non-Docker environments. This creates local CI validation gaps. Consider a story to make integration tests runnable in both Docker and non-Docker modes (e.g., using testcontainers or conditional skip logic).

## Metrics

- Stories accepted first try: 2/2 (100%)
- Stories rejected at least once: 0
- Most common rejection reason: N/A (no rejections)
- Test gap learnings captured: 0 (all tests comprehensive)
- Unrelated fixes during implementation: 1 (spike_redeemer.go compile errors)

## What Went Well

1. **Clear AC verification tables** - Both stories included detailed AC verification tables mapping requirements to code locations and test locations. This made PM acceptance fast and confident.

2. **Comprehensive integration tests** - RFA-pkm.1 included real Groq API integration tests with multiple payload types. This caught the response format discrepancy early.

3. **Walking skeleton before complexity** - RFA-pkm.1 established the basic Groq integration before RFA-pkm.2 added chunking complexity. This vertical slice approach prevented integration surprises.

4. **Bounded concurrency test coverage** - RFA-pkm.2 included a test specifically for bounded concurrency (peak=3, max=3) with mutex-guarded counter and sleep-based overlap verification. This proves the semaphore works correctly.

5. **Defensive parsing** - parsePromptGuardContent handles both numeric scores (actual) and class labels (documented), making the integration resilient to API changes.

## What Could Improve

1. **Debug artifact cleanup** - fmt.Printf from RFA-pkm.1 persisted into RFA-pkm.2. Need systematic cleanup pass or linter rule to catch these.

2. **Integration test portability** - TestDeepScanMiddlewareIntegration requires Docker and always skips in non-Docker environments. This creates blind spots in local CI.

3. **Unrelated fixes during story** - spike_redeemer.go compile errors were fixed as part of RFA-pkm.1 to unblock the build. Ideally these would be separate commits, but pragmatically this was necessary.

4. **Documentation drift** - HuggingFace docs vs Groq API actual behavior diverged. We handle this defensively, but upstream documentation accuracy is out of our control.

## Key Takeaways

- **Real API testing in walking skeletons is CRITICAL** - Without real Groq API calls in RFA-pkm.1, we wouldn't have discovered the response format discrepancy until later.
- **Defensive parsing pays off** - Handling multiple response formats prevents fragile integrations and makes the code resilient to API changes.
- **AC verification tables accelerate PM acceptance** - Clear mapping of requirements to code and tests makes review fast and confident.
- **Walking skeleton + feature extension** is a proven pattern - Get the basic integration working end-to-end (RFA-pkm.1), then add complexity (RFA-pkm.2).
