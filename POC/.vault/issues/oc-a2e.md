---
id: oc-a2e
title: "GAP-4: Wire deep scan async alerts to hash-chained audit log"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:21:27Z
created_by: ramirosalas
updated_at: 2026-02-27T03:52:01Z
content_hash: "sha256:ac97d85a1205a21992afa76a45d04816c7f04c1d860c9ba46fcc33a2abaef352"
closed_at: 2026-02-21T03:43:22Z
close_reason: "Deep scan async alerts now emit to hash-chained audit log. Unit + integration tests with SHA-256 chain verification."
blocked_by: [oc-kxh]
blocks: [oc-vh5]
---

## Description
WHAT: Replace the fmt.Printf placeholder in DeepScanner.ResultProcessor() with an actual call to the Auditor.Log() method, persisting high-score injection/jailbreak alerts to the hash-chained audit log.

WHY: The deep scan middleware has TWO code paths: (1) a synchronous path in DeepScanMiddleware() that evaluates and blocks/allows requests -- this path ALREADY calls emitAuditEvent() and logs to the audit chain. (2) An async path in ResultProcessor() that processes results from a background goroutine via a buffered channel (d.resultChan). The async path currently has 'fmt.Printf("ALERT: ...")' at line 774 of deep_scan.go and a comment 'For POC: this is a placeholder' at line 779. This means high-score alerts detected asynchronously are NOT persisted to the tamper-evident audit log. A code reviewer will see this placeholder and question the audit chain's completeness.

HOW:
1. In internal/gateway/middleware/deep_scan.go, in the ResultProcessor() method (line 758):
   - After the shouldTriggerAlert() check (line 771), call d.emitAuditEvent() to persist the alert to the audit chain
   - Replace the fmt.Printf on line 774 with the emitAuditEvent call
   - The emitAuditEvent() method already exists (line 684) and accepts: ctx context.Context, result DeepScanResult, reason string, blocked bool, injThreshold float64, jbThreshold float64
   - For the async path, create a background context since there is no request context available: use context.Background()
   - For 'reason' parameter, use 'async_alert_high_score'
   - For 'blocked', use false (the async path does not block -- the request was already forwarded)
   - For thresholds, use the DeepScanner's configured thresholds (you may need to store injectionThreshold and jailbreakThreshold on the DeepScanner struct if not already accessible -- check the struct fields)
   - Remove the 'For POC: this is a placeholder' comment on line 779
   - Remove the bare fmt.Printf call entirely

2. Verify the DeepScanner struct has access to the threshold values needed by emitAuditEvent. The thresholds are currently configured via the middleware's RiskConfig. If the DeepScanner does not store thresholds, add fields injectionThreshold and jailbreakThreshold (float64) to the DeepScanner struct and set them during construction in NewDeepScannerWithConfig().

TECHNICAL CONTEXT:
- The Auditor type is in internal/gateway/middleware/audit.go
- Auditor.Log(event AuditEvent) is the public method (line 177 of audit.go)
- emitAuditEvent (line 684 of deep_scan.go) is an existing private method on DeepScanner that already formats and logs to the audit chain
- The audit chain is hash-chained: each event's PrevHash field contains the SHA-256 of the previous event, creating a tamper-evident log
- The ResultProcessor goroutine is started at gateway.go:326 via 'go deepScanner.ResultProcessor(context.Background())'
- The shouldTriggerAlert function checks if injection/jailbreak scores exceed thresholds

FILES TO MODIFY:
- MODIFY: internal/gateway/middleware/deep_scan.go (ResultProcessor method, possibly DeepScanner struct)

TESTING REQUIREMENTS:
- Unit test: Write a test that creates a DeepScanner with a test Auditor, sends a high-score DeepScanResult through the resultChan, and verifies the Auditor receives an audit event with event_type containing 'deep_scan' and the correct scores. This can use a mock/spy Auditor.
- Integration test: Use the existing deep_scan_integration_test.go pattern. Create a DeepScanner with a real Auditor writing to a temp JSONL file. Send a high-score result through resultChan. Wait for ResultProcessor to process it. Read the JSONL file and verify the alert event is present with correct hash chain integrity.
- Both tests go in: internal/gateway/middleware/deep_scan_test.go (unit), tests/integration/deep_scan_integration_test.go (integration)

MANDATORY SKILLS TO REVIEW:
- None identified. The existing emitAuditEvent pattern is the exact template to follow.

## Acceptance Criteria
AC1: ResultProcessor() calls emitAuditEvent() (or equivalent Auditor.Log()) for high-score alerts instead of fmt.Printf
AC2: The fmt.Printf('ALERT: ...') call on line 774 and the placeholder comment on line 779 are removed
AC3: Async alert events appear in the JSONL audit log with proper hash chain linking (prev_hash field set)
AC4: A unit test verifies high-score results trigger audit event emission in the async path
AC5: An integration test verifies the full flow: high-score result -> resultChan -> ResultProcessor -> JSONL file with hash chain integrity
AC6: Existing deep_scan tests pass unchanged

## Design


## Notes


## History
- 2026-02-27T03:51:55Z dep_added: blocks oc-vh5

## Links
- Blocks: [[oc-vh5]]
- Blocked by: [[oc-kxh]]

## Comments
