
---

## [Added from Epic RFA-pkm retro - 2026-02-06]

### Defensive API Response Parsing for Third-Party Services

**Priority:** Critical

**Context:** When integrating Groq Prompt Guard 2, the actual API response format (numeric scores as text: "0.9996") differed from HuggingFace documentation (class labels: "INJECTION"). The parsePromptGuardContent function was made robust to handle both formats, preventing integration brittleness.

**Recommendation:** For all third-party API integrations (especially ML models via proxy services like Groq, Replicate, OpenRouter):
1. **Test with real API early** - Include real API integration tests in the walking skeleton, don't wait until feature completion
2. **Implement defensive parsing** - Handle multiple plausible response formats, not just the documented one
3. **Add integration tests with real API calls** - Catch format drift and documentation discrepancies
4. **Document actual observed format** - Code comments should reflect what the API actually returns, with references to any documentation discrepancies

**Applies to:** All stories involving third-party API integration, especially ML model inference, authentication services, payment gateways, external data sources

**Source stories:** RFA-pkm.1


---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### Always use canonical library patterns for security-critical code

**Priority:** Critical

**Context:** When integrating go-spiffe for mTLS client setup, manual SVID extraction via `GetX509SVID()` / `GetX509BundleForTrustDomain()` was attempted, requiring complex error handling. The go-spiffe library provides `tlsconfig.MTLSClientConfig()` which handles this correctly and is the canonical pattern.

**Recommendation:** For all future mTLS or SPIFFE integrations:
1. **First check the library's canonical patterns** before writing custom code
2. Use `tlsconfig.MTLSClientConfig()` for mTLS client setup in go-spiffe v2
3. Avoid manual SVID extraction unless the library doesn't provide a higher-level API
4. Document the canonical pattern in ARCHITECTURE.md when first used

**Applies to:** All stories involving SPIFFE, mTLS, or security-critical external libraries

**Source stories:** RFA-a2y.1

