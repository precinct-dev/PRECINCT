---
id: oc-kxh
title: "GAP-1: Enable automated CI with build-and-test workflow"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:20:23Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:208de48db098aeca0de0fb9de339fa91a1c61f9488cd09ba974cd13cfb94a2ba"
closed_at: 2026-02-21T03:35:08Z
close_reason: "CI workflow created and pushed. All 14 test packages pass. Security scan triggers uncommented. Two drifted tests fixed."
blocks: [oc-4sr, oc-a2e, oc-d1t, oc-h5t, oc-vh5]
---

## Description
WHAT: Create a new GitHub Actions workflow (.github/workflows/ci.yml) that runs 'go test ./...' and 'go vet ./...' on every push to main and every PR targeting main. Also uncomment the push/PR triggers in the existing .github/workflows/security-scan.yml (currently manual-only via workflow_dispatch).

WHY: The POC has 1,332 test functions across 62k lines of test code, but ZERO automated regression. Every push to main is unvalidated. This is the single most impactful credibility gap -- a reviewer will check GitHub Actions first. Without CI, all subsequent gap-fix PRs land without automated validation.

HOW:
1. Create .github/workflows/ci.yml with:
   - Triggers: push to main, pull_request targeting main
   - Job 1 'test': checkout, setup-go (go-version-file: go.mod, cache: true), run 'go vet ./...', run 'go test -race -count=1 ./...'
   - Job 2 'build': checkout, setup-go, run 'go build ./...'
   - Use ubuntu-latest runner
   - Set permissions: contents: read
   - Add -race flag to catch data races (the gateway uses heavy concurrency with goroutines for async audit, deep scan, MCP transport)

2. Modify .github/workflows/security-scan.yml:
   - Uncomment lines 4-11 (the pull_request and push triggers)
   - Keep workflow_dispatch as an additional trigger
   - Result: security scans run on PR + push AND can still be triggered manually

TECHNICAL CONTEXT:
- Go version: 1.24.6 (from go.mod)
- The project uses go.mod at repository root (POC/)
- Tests include both unit tests in internal/gateway/middleware/*_test.go and integration tests in tests/integration/*_test.go
- Integration tests use httptest (no external dependencies) so they can run in CI without Docker
- The Makefile already has a 'test' target but it is not wired to CI

FILES TO MODIFY:
- CREATE: .github/workflows/ci.yml
- MODIFY: .github/workflows/security-scan.yml (uncomment lines 4-11)

TESTING REQUIREMENTS:
- Unit test: N/A (this is CI infrastructure)
- Integration test: Push a test commit to a branch, open a PR targeting main, verify both workflows trigger. Verify 'go test ./...' passes. Verify 'go vet ./...' passes. Capture screenshot of green CI checks as evidence.
- Acceptance gate: PR to main shows green check from ci.yml workflow

MANDATORY SKILLS TO REVIEW:
- None identified. Standard GitHub Actions patterns, no specialized skill requirements.

## Acceptance Criteria
AC1: .github/workflows/ci.yml exists and triggers on push to main and PR to main
AC2: ci.yml runs 'go vet ./...' and 'go test -race -count=1 ./...' and 'go build ./...'
AC3: .github/workflows/security-scan.yml has push and pull_request triggers uncommented (workflow_dispatch retained)
AC4: Both workflows use go-version-file: go.mod with cache: true
AC5: A test PR shows both workflows running and passing

## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocks oc-vh5

## Links
- Blocks: [[oc-4sr]], [[oc-a2e]], [[oc-d1t]], [[oc-h5t]], [[oc-vh5]]

## Comments
