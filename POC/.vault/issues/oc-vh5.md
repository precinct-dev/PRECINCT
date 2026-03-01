---
id: oc-vh5
title: "GAP-2: Replace unstructured logging with log/slog"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:22:09Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:9de26dea1d435769a4c2c8f902dcf3b130adb03fa6f8fe3f3cdb4f4d42aef117"
closed_at: 2026-02-21T10:16:58Z
close_reason: "All log.Printf/fmt.Printf replaced with slog across 13 production files. Centralized logger in logging.go with JSON handler. Unit + integration tests. Zero grep results for log.Printf in production code."
blocks: [oc-4sr]
blocked_by: [oc-a2e, oc-kxh]
---

## Description
WHAT: Replace all production log.Printf and fmt.Printf calls in the gateway and middleware packages with Go's stdlib log/slog package for structured JSON logging. This covers approximately 58 calls in production code (excludes test files which use fmt.Printf for benchmark output and are acceptable).

WHY: Production gateway code uses log.Printf and fmt.Printf for operational logging. This means log aggregation requires regex parsing, there is no structured context (no JSON fields for request IDs, SPIFFE IDs, middleware names), and the logging is not queryable by log aggregation tools. log/slog is in the Go stdlib since 1.21 and the project uses Go 1.24.6. Structured logging is table-stakes for any production security gateway.

HOW:
1. Create a shared logger initialization in internal/gateway/logging.go (new file):
   - Create a function InitLogger(jsonOutput bool) that configures slog.SetDefault() with a slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
   - This centralizes logger configuration so all packages use the same handler
   - Export a package-level function or use slog.Default() throughout

2. In internal/gateway/gateway.go (approximately 12 log.Printf calls):
   - Replace startup/config logging: log.Printf('SPIFFE mode: %s', ...) -> slog.Info('spiffe mode configured', 'mode', cfg.SPIFFEMode)
   - Replace warning logging: log.Printf('WARNING: ...') -> slog.Warn(...)
   - Add structured fields: include relevant context (config paths, SPIFFE IDs, component names) as typed key-value pairs
   - Call InitLogger() early in NewGateway() or the gateway's initialization path

3. In internal/gateway/middleware/audit.go (3 log.Printf calls):
   - Replace error logging: log.Printf('ERROR: Failed to marshal...') -> slog.Error('failed to marshal audit event', 'error', err)
   - These are all error-path logging in the async writer goroutine

4. In internal/gateway/middleware/opa_engine.go (6 log.Printf calls):
   - Replace warning logging: log.Printf('Warning: failed to read data file...') -> slog.Warn('failed to read data file', 'file', file.Name(), 'error', err)
   - Replace info logging: log.Printf('OPA policies loaded...') -> slog.Info('opa policies loaded', 'directory', e.policyDir)

5. In internal/gateway/middleware/deep_scan.go (1 fmt.Printf call -- the one at line 774):
   - NOTE: This is ALSO covered by the GAP-4 story (oc-a2e). If GAP-4 is completed first, this call will already be replaced with an audit event. If this story executes first, replace it with slog.Warn('deep scan alert', 'request_id', result.RequestID, 'injection_score', result.InjectionScore, 'jailbreak_score', result.JailbreakScore). The GAP-4 story will then replace this slog call with the audit event.
   - Coordinate: this story and GAP-4 touch the same line. Use 'blocks' dependency to serialize them.

6. In internal/gateway/middleware/gdpr_delete.go (1 log.Printf call):
   - Replace: log.Printf('GDPR_DELETION: ...') -> slog.Info('gdpr deletion completed', 'spiffe_id', spiffeID, 'sessions_found', count, 'keys_deleted', deleted)

7. In all other middleware files with log.Printf/fmt.Printf calls:
   - Follow the same pattern: structured key-value pairs, appropriate level (Info/Warn/Error)
   - DO NOT touch test files (_test.go) -- fmt.Printf in benchmark_test.go is for human-readable benchmark output and is acceptable

TECHNICAL CONTEXT:
- Go 1.24.6 has full log/slog support (stdlib since 1.21)
- slog.Info/Warn/Error take a message string followed by alternating key-value pairs: slog.Info('msg', 'key1', val1, 'key2', val2)
- slog.SetDefault() configures the default logger used by slog.Info() etc.
- The JSON handler outputs one JSON object per log line, compatible with any log aggregator
- DO NOT import third-party logging libraries (zerolog, zap, etc.) -- slog is sufficient and avoids new dependencies

FILES TO MODIFY:
- CREATE: internal/gateway/logging.go (logger initialization)
- MODIFY: internal/gateway/gateway.go
- MODIFY: internal/gateway/middleware/audit.go
- MODIFY: internal/gateway/middleware/opa_engine.go
- MODIFY: internal/gateway/middleware/deep_scan.go (coordinate with GAP-4)
- MODIFY: internal/gateway/middleware/gdpr_delete.go
- MODIFY: any other files in internal/gateway/ or internal/gateway/middleware/ that contain log.Printf or fmt.Printf in production (non-test) code

FILES NOT TO MODIFY:
- internal/gateway/middleware/benchmark_test.go (fmt.Printf for human-readable benchmark output is acceptable)
- Any *_test.go file

TESTING REQUIREMENTS:
- Unit test: Write a test in internal/gateway/logging_test.go that verifies InitLogger produces JSON output by capturing slog output to a buffer and parsing it as JSON
- Integration test: Extend an existing integration test (e.g., tests/integration/gateway_integration_test.go) to verify that after processing a request, the gateway's stdout contains valid JSON log lines with expected structured fields (at minimum: 'msg', 'level', 'time')
- Verify: 'go test -race ./...' passes with zero failures
- Verify: no remaining log.Printf or fmt.Printf calls in production code (grep -rn 'log.Printf\|fmt.Printf' internal/gateway/ --include='*.go' | grep -v _test.go should return zero results, or only results from files explicitly excluded)

MANDATORY SKILLS TO REVIEW:
- None identified. log/slog is Go stdlib, well-documented at pkg.go.dev/log/slog.

## Acceptance Criteria
AC1: All log.Printf calls in internal/gateway/gateway.go replaced with slog equivalents
AC2: All log.Printf calls in internal/gateway/middleware/*.go (non-test) replaced with slog equivalents
AC3: All fmt.Printf calls in production code (non-test) replaced with slog equivalents
AC4: Logger initialization centralized in internal/gateway/logging.go using slog.NewJSONHandler
AC5: A unit test verifies JSON log output format
AC6: An integration test verifies structured log fields appear during request processing
AC7: 'grep -rn log.Printf\|fmt.Printf internal/gateway/ --include=*.go | grep -v _test.go' returns zero results (or only explicitly documented exceptions)
AC8: 'go test -race ./...' passes with zero failures
AC9: No third-party logging libraries introduced

## Design


## Notes


## History
- 2026-02-27T03:51:55Z dep_added: blocked_by oc-kxh

## Links
- Blocks: [[oc-4sr]]
- Blocked by: [[oc-a2e]], [[oc-kxh]]

## Comments
