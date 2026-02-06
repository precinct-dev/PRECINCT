
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
