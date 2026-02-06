
---

## [Added from Epic RFA-a2y retro - 2026-02-06]

### Signature changes require coordination across all call sites

**Priority:** Important

**Context:** Changing the TokenSubstitution middleware signature to add a SecretRedeemer parameter required updating 7 call sites across 4 files. The dependency injection is cleaner, but the coordination overhead was significant.

**Recommendation:** When changing widely-used function signatures:
1. **Use `grep -r "FunctionName(" .` to find all call sites** before making the change
2. Consider backward-compatible approaches first (e.g., new function name, deprecate old)
3. If signature change is unavoidable, update ALL call sites in the same commit
4. List affected files in the commit message for auditability

**Applies to:** All stories modifying shared middleware, utilities, or core functions

**Source stories:** RFA-a2y.1


---

## [Added from Epic RFA-pkm retro - 2026-02-06]

### AC Verification Tables Accelerate PM Acceptance

**Priority:** Important

**Context:** Both RFA-pkm.1 and RFA-pkm.2 included detailed AC verification tables in delivery notes, mapping each acceptance criterion to code location, test location, and status. PM-Acceptor was able to review and accept both stories on first delivery with high confidence.

**Recommendation:** For all story deliveries, include an AC verification table in the DELIVERED section with this format:

```
| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | [Exact AC text] | file.go:lines (brief description) | test.go:TestName (lines) | PASS |
```

This table provides:
- **Traceability** - Direct mapping from requirement to implementation to test
- **Reviewability** - PM can spot-check specific ACs without searching codebase
- **Confidence** - Clear evidence that each AC was addressed and tested

**Applies to:** All story deliveries, especially stories with multiple ACs or complex acceptance criteria

**Source stories:** RFA-pkm.1, RFA-pkm.2

### Debug Artifacts Accumulate Without Systematic Cleanup

**Priority:** Nice-to-have

**Context:** fmt.Printf debug statement in ResultProcessor (deep_scan.go:644) from RFA-pkm.1 persisted into RFA-pkm.2. Debug artifacts accumulate during rapid development and aren't systematically removed.

**Recommendation:** 
1. **Pre-delivery review** - Before marking story as delivered, grep for debug artifacts: `fmt.Print`, `console.log`, `TODO`, `FIXME`, `XXX`
2. **Linter rules** - Add golangci-lint rules to catch common debug artifacts (forbidigo for fmt.Print*, gocritic for commentFormatting)
3. **Backlog grooming** - Periodically create cleanup stories to audit for accumulated debug artifacts
4. **Structured logging** - Use structured logging (zerolog, zap) instead of fmt.Print* so linters can enforce it

**Applies to:** All stories, especially rapid iteration epics with multiple related stories

**Source stories:** RFA-pkm.1, RFA-pkm.2


---

## [Added from Epic RFA-hh5 retro - 2026-02-06]

### Commit atomically per story

**Priority:** Critical

**Context:** RFA-hh5.1 observed that commit 5a25a09 bundled changes from multiple stories, making PM acceptance harder since AC verification requires examining which code belongs to which story. RFA-hh5.2 observed similar issues with auto-save hooks modifying unrelated files.

**Recommendation:** Developers MUST commit atomically per story. One story = one commit (or logically grouped commits for that story only). Do NOT bundle unrelated changes, even if they're "needed for buildability". If Story B requires changes from Story A, either: (1) complete and deliver Story A first, or (2) raise a dependency blocker to Sr. PM.

**Applies to:** All stories during execution phase.

**Source stories:** RFA-hh5.1, RFA-hh5.2

### Disable auto-instrumentation during story execution

**Priority:** Important

**Context:** RFA-hh5.2 mentioned a save hook from RFA-m6j.2 that auto-instruments middleware with OTel spans on every file save, modifying unrelated files and making atomic commits harder.

**Recommendation:** Auto-save hooks or formatters that modify multiple unrelated files (e.g., auto-adding instrumentation) should be disabled during story execution or configured to only affect files explicitly touched by the developer. If auto-instrumentation is needed, run it as a separate post-story task, not during active development.

**Applies to:** Developer tooling configuration, auto-formatters, linters with auto-fix.

**Source stories:** RFA-hh5.2

---

## [Added from Epic RFA-m6j retro - 2026-02-06]

### Verify clean working tree before starting story

**Priority:** Critical

**Context:** Pre-existing KeyDB store refactor changes were uncommitted in the working tree and got auto-merged during linter processing in RFA-m6j.1, accidentally including unrelated changes in the commit.

**Recommendation:** Developers MUST verify clean working tree (`git status`) before starting story implementation. If uncommitted changes exist, either commit them separately or stash them. Never start story work with a dirty working tree.

**Applies to:** All stories

**Source stories:** RFA-m6j.1

### Developer delivery checklist must include push verification

**Priority:** Important

**Context:** RFA-m6j.3 was rejected once for missing remote push (developer forgot `git push`), then accepted on redelivery after push.

**Recommendation:** Developer delivery checklist should explicitly include "Verify commit pushed to remote (`git log origin/epic/<epic-id>..HEAD` must be empty)". This is a mechanical step that shouldn't cause rejections.

**Applies to:** All stories

**Source stories:** RFA-m6j.3

---

## [Added from Epic RFA-8z8 retro - 2026-02-06]

### Verify git diff before committing to avoid bundling unrelated changes

**Priority:** Important

**Context:** RFA-8z8.2 discovered that gateway.go changes had been committed in a prior session, causing confusion about what needed committing. When developer agents run concurrently or sessions overlap, changes can be accidentally bundled.

**Recommendation:** Developer agents should ALWAYS run `git diff` before committing to verify:
1. Only the current story's changes are staged
2. No unrelated changes from concurrent agents are included
3. If unexpected changes appear, investigate (don't blindly commit)
4. If changes belong to another story, coordinate or alert orchestrator

**Applies to:** All stories when multiple developer agents are active or sessions overlap

**Source stories:** RFA-8z8.2
