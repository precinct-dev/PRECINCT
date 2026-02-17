# Acceptance Criteria Method: Baseline Failures

## Purpose

When a story has known pre-existing test failures, acceptance criteria must
distinguish baseline failures from regressions. This avoids impossible ACs such
as "all tests pass" when the story itself acknowledges known failing tests.

## Problem Pattern

- Story context says some tests are already failing.
- AC text still says "all tests pass".
- PM acceptance becomes ambiguous and inconsistent.

## Required Pattern

Use explicit baseline language in both story context and acceptance criteria.

1. Declare the baseline failures in context:
   - Include exact test identifiers (names or numbers).
2. Write ACs against regression-free behavior:
   - "All tests pass OR only baseline failures remain."
3. Require proof against that baseline:
   - Command output must show no new failures outside baseline.

## AC Templates

Use one of these templates when baseline failures exist:

- `AC: Demo/test suite passes with no new failures beyond baseline: <list>.`
- `AC: All tests pass OR only known baseline failures <list> remain.`
- `AC: Story introduces zero net-new failures in <suite>; baseline failures <list> are unchanged.`

## Testing Requirement Template

Include this in story testing requirements:

- `Run: <exact command>`
- `Expected: pass, or only baseline failures <list>`
- `Reject if: any failure outside baseline appears`

## PM Acceptance Rule

Accept only when both are true:

1. Story explicitly lists baseline failures.
2. Evidence proves no failures beyond that baseline.

Reject when:

- AC says "all pass" but baseline failures are acknowledged.
- Test evidence does not separate baseline failures from new ones.

## Good vs Bad Examples

Good:

- `AC: make demo-compose completes with no new failures beyond baseline tests 11,13,14,15,16.`

Good:

- `AC: All 21 Go tests pass OR only baseline failures 11,13,14,15,16 remain.`

Bad:

- `AC: All 21 Go tests pass.` (while story context says 5 tests are pre-failing)

## Copy/Paste Snippet for New Stories

```markdown
### Baseline Failures
- Known pre-existing failures: <list>

### Acceptance Criteria
- [ ] Test suite passes with no failures beyond baseline: <list>

### Testing Requirements
- Run: <command>
- Expected: all pass, or only baseline failures <list>
- Reject if any additional failure appears
```

## Evidence Path Guard (Pre-Acceptance)

Before PM acceptance, validate that backticked `POC/...` evidence paths referenced
in story notes still exist in the tracked repository.

- Command:
  - `make -C POC story-evidence-validate STORY_ID=<story-id>`
- Script:
  - `POC/tests/e2e/validate_story_evidence_paths.sh`

Reject or reconcile the story if this check reports missing files.
