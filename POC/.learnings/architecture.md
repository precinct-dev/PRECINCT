
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
