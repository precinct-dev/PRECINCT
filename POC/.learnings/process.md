
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

