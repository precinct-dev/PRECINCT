---
id: oc-h5t
title: "GAP-6: Extract deterministic demo assertions into CI-runnable integration tests"
status: closed
priority: 2
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:23:35Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:ee954646509c327eb21dadf25b1f84e9de3d0235eec42e3d4392fa45a1745704"
closed_at: 2026-02-21T09:57:22Z
close_reason: "Delivered 18/28 demo assertions as httptest integration tests across 4 files (DLP, OPA, rate limit, registry). All pass with -race -count=1, zero regressions, no mocks, demo/go/main.go unmodified."
blocked_by: [oc-kxh]
---

## Description
WHAT: Extract the deterministic test assertions from demo/go/main.go into new httptest-based integration tests in tests/integration/. Focus on the tests that validate DLP redaction, OPA policy denial, rate limiting behavior, and tool registry verification -- these are assertions that do not require external services and can run against an in-process httptest server.

WHY: The demo exerciser (demo/go/main.go) has 28 tests that require the full Docker Compose stack to run. Many of these assertions are inherently deterministic: they send a known payload and check for a specific response code or body pattern. Extracting these into httptest-based tests means CI can validate them on every push without needing Docker Compose, increasing regression coverage from the existing 1,332 test functions.

HOW:
1. Review demo/go/main.go and identify which test cases have deterministic assertions:
   - DLP tests: Send payloads containing SSN/credit card patterns, verify they are redacted or blocked
   - OPA tests: Send requests with unauthorized SPIFFE IDs, verify 403 denial
   - Rate limit tests: Send burst of requests exceeding rate limit, verify 429 response
   - Registry tests: Send requests for unregistered tools, verify denial
   - These tests use the Go SDK at github.com/example/mcp-gateway-sdk-go/mcpgateway but the assertions are about HTTP responses

2. Create tests/integration/demo_extracted_dlp_test.go:
   - Use the existing httptest gateway pattern from tests/integration/gateway_integration_test.go
   - Replicate the DLP test assertions: send payloads with PII patterns, verify redaction in response
   - Use real DLP scanner (no mocks) configured with the same patterns as production

3. Create tests/integration/demo_extracted_opa_test.go:
   - Use embedded OPA engine with production policy files (config/opa/mcp_policy.rego)
   - Send requests with various SPIFFE IDs, verify allow/deny matches demo expectations

4. Create tests/integration/demo_extracted_ratelimit_test.go:
   - Use real rate limiter configured with known limits
   - Send burst exceeding limit, verify 429 response codes

5. Create tests/integration/demo_extracted_registry_test.go:
   - Use real tool registry loaded from config/opa/tool_grants.yaml
   - Send requests for registered and unregistered tools, verify responses

TECHNICAL CONTEXT:
- The existing tests/integration/ directory has 60+ integration test files using httptest pattern
- The test helpers in tests/integration/test_helpers_test.go provide gateway setup utilities
- Demo test cases in demo/go/main.go use the Go SDK but the underlying assertions are HTTP-level
- The walking_skeleton_test.go in tests/integration/ already demonstrates the full middleware chain in httptest
- Focus on extracting ASSERTIONS, not the demo UI/output -- we want the validation logic, not the colored terminal output

FILES TO MODIFY:
- CREATE: tests/integration/demo_extracted_dlp_test.go
- CREATE: tests/integration/demo_extracted_opa_test.go
- CREATE: tests/integration/demo_extracted_ratelimit_test.go
- CREATE: tests/integration/demo_extracted_registry_test.go
- DO NOT MODIFY: demo/go/main.go (the demo stays as-is for stakeholder demos)

TESTING REQUIREMENTS:
- The new tests ARE the integration tests -- they must pass with 'go test -race ./tests/integration/...'
- Each new test file must use real middleware (no mocks) following the existing httptest pattern
- Verify the new tests pass in CI (the GAP-1 ci.yml workflow will run them automatically)

MANDATORY SKILLS TO REVIEW:
- None identified. Standard Go httptest patterns, following existing test_helpers_test.go conventions.

## Acceptance Criteria
AC1: At least 4 new integration test files created in tests/integration/ covering DLP, OPA, rate limit, and registry assertions
AC2: Each test uses real middleware (no mocks) with httptest
AC3: All new tests pass with 'go test -race ./tests/integration/...'
AC4: demo/go/main.go is NOT modified
AC5: New tests cover at least 10 of the 28 demo assertions (the deterministic subset)
AC6: 'go test -race ./...' passes with zero failures

## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocked_by oc-kxh

## Links
- Blocked by: [[oc-kxh]]

## Comments
