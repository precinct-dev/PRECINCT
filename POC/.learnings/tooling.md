
---

## [Added from Epic RFA-pkm retro - 2026-02-06]

### Go Numeric Constant Type Conversion Handling

**Priority:** Important

**Context:** Go untyped float constants (like `tokensPerWord=1.3`) cause vet errors when used in constant expressions involving `int()` conversion. This is a Go language constraint where constant expressions must be fully evaluable at compile time with exact types.

**Recommendation:** When writing Go code with numeric conversions involving floating-point constants:
1. **Assign constants to variables first** before using them in type conversion expressions (`tokenCount := int(float64(wordCount) * tokensPerWord)`)
2. **Use explicit type declarations** for numeric constants: `const tokensPerWord float64 = 1.3`
3. **Prefer runtime evaluation** over constant expressions for mixed-type math
4. **Run `go vet` locally** before delivery to catch these issues early

**Applies to:** All Go stories involving numeric computation, especially token counting, rate limiting, resource allocation, quota management

**Source stories:** RFA-pkm.2


---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### E2E scripts should handle API authentication gracefully

**Priority:** Nice-to-have

**Context:** The SPIKE Nexus E2E script had to handle both direct API access and docker exec fallback because SPIKE Nexus may enforce mTLS for write operations (secret/put) even in POC mode.

**Recommendation:** For E2E scripts calling external APIs:
1. **Try the API call first** (assume best case)
2. If it fails with 401/403, fall back to docker exec or other authenticated path
3. Log which path was used for debugging
4. Document the fallback behavior in script comments

**Applies to:** E2E validation scripts for services with authentication

**Source stories:** RFA-a2y.2


---

## [Added from Epic RFA-hh5 retro - 2026-02-06]

### bitnami/keydb uses keydb-cli not redis-cli

**Priority:** Nice-to-have

**Context:** RFA-hh5.1 noted that bitnami/keydb uses "keydb-cli" (not "redis-cli") for healthcheck commands in Docker Compose.

**Recommendation:** When adding Redis/KeyDB services to Docker Compose, use "keydb-cli" for bitnami/keydb healthchecks, not "redis-cli". Document this in docker-compose.yml comments to prevent confusion.

**Applies to:** Docker Compose configurations for Redis/KeyDB services.

**Source stories:** RFA-hh5.1

### Clean up unused imports after refactoring

**Priority:** Nice-to-have

**Context:** RFA-hh5.2 observed that golang.org/x/time/rate is no longer used after refactoring to KeyDB-based rate limiting, but the import remains.

**Recommendation:** When refactoring removes a dependency, clean up unused imports in the same commit. Use tools like `goimports -w .` or `go mod tidy` as part of delivery checklist.

**Applies to:** All refactoring stories, particularly those replacing libraries or algorithms.

**Source stories:** RFA-hh5.2

---

## [Added from Epic RFA-m6j retro - 2026-02-06]

### Verify config field types before writing test assertions

**Priority:** Nice-to-have

**Context:** DeepScannerConfig.FallbackMode is a string type, not the DeepScanFallbackMode const type that tests initially assumed.

**Recommendation:** When writing tests for config structs, verify actual field types in the codebase before writing type assertions. Don't assume enum types without checking the struct definition.

**Applies to:** All config testing stories

**Source stories:** RFA-m6j.2

---

## [Added from Epic RFA-8z8 retro - 2026-02-06]

### TLS proxy pattern for testing services with non-TLS-aware mocks

**Priority:** Nice-to-have

**Context:** miniredis (the standard in-memory Redis mock for Go) doesn't support TLS. The pattern of creating a TLS listener that proxies to the plaintext mock was proven in keydb_tls_test.go. This pattern generalizes to any mock that lacks TLS support.

**Recommendation:** For testing TLS connections when the mock doesn't support TLS:
1. Create a net.Listener with tls.Config (real TLS handshake)
2. Accept connections, proxy bytes to/from the non-TLS mock
3. This allows real TLS handshake testing without needing a TLS-capable mock
4. Document this pattern in testing guidelines for future reference

**Applies to:** Stories testing TLS connections where no TLS-capable mock exists

**Source stories:** RFA-8z8.2

---

## [Added from Epic RFA-8jl retro - 2026-02-06]

### PyYAML is not in Python stdlib

**Priority:** Important

**Context:** RFA-8jl.1 story description said "No additional pip dependencies" but YAML parsing requires PyYAML. Always verify stdlib claims for specific formats.

**Recommendation:** When scoping Python stories, remember that YAML, TOML (pre-3.11), and other common formats may require pip packages. Create requirements.txt and use Makefile venv auto-provisioning: `$(VENV): requirements.txt` ensures dependencies are always current.

**Applies to:** All Python stories that process structured data formats

**Source stories:** RFA-8jl.1

### fpdf2 API differs from legacy fpdf documentation

**Priority:** Nice-to-have

**Context:** fpdf2 (maintained fork) uses `new_x`/`new_y` parameters for cell positioning instead of the deprecated `ln` parameter from legacy fpdf.

**Recommendation:** When using fpdf2, use `new_x=XPos.LEFT, new_y=YPos.NEXT` instead of `ln=True`. Reference fpdf2 docs, not legacy fpdf docs.

**Applies to:** All stories generating PDF reports with fpdf2

**Source stories:** RFA-8jl.2

### Docker-compose log lines have container prefix before JSON

**Priority:** Important

**Context:** Docker-compose audit log lines have container name + timestamp prefix before the JSON payload. The parser must strip everything up to the first `{` character.

**Recommendation:** When processing log files from containerized services, always account for container runtime prefixes. Test with real docker-compose output, not just the expected JSON format.

**Applies to:** All stories parsing logs from docker-compose services

**Source stories:** RFA-8jl.1
