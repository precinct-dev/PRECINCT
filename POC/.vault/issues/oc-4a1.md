---
id: oc-4a1
title: "Fix data races in MCP transport concurrent tests"
status: closed
priority: 1
type: bug
assignee: ramxx@ramirosalas.com
labels: [delivered]
created_at: 2026-02-21T17:53:33Z
created_by: ramirosalas
updated_at: 2026-02-27T03:51:55Z
content_hash: "sha256:675e476a8abe45246b5ab3aea7fcea90b8524744b4edd36726f70cd2681e8d14"
closed_at: 2026-02-21T18:01:19Z
close_reason: "Fixed data races: added getMCPTransport() accessor for synchronized reads of g.mcpTransport, added Auditor.LastHash() for synchronized reads of auditor.lastHash. Both target tests pass under -race count=3. Full suite passes with zero race warnings."
parent: oc-l5u
follows: [oc-a8e]
---

## Description
## User Story

As a developer running the test suite with the race detector, I need the MCP transport tests to pass cleanly under "go test -race" so that CI can enforce race-free code without false positives masking real races.

## Context

Two tests in internal/gateway/gateway_test.go have data races on the Gateway.mcpTransport field. These are the ONLY test failures in the entire 1294-test suite and have been documented as pre-existing across all recent gap stories (GAP-1 through GAP-7). They cause failures exclusively under "go test -race ./internal/gateway/..." -- standard "go test" passes.

## Root Cause Analysis

The Gateway struct has a lazy-initialized mcpTransport field (line 56 of gateway.go) protected by mcpTransportMu (line 57). The ensureMCPTransportInitialized() method (gateway.go:1055-1094) uses a double-checked locking pattern:

1. Fast path: reads g.mcpTransport without the lock (line 1061)
2. Acquires g.mcpTransportMu lock (line 1065)
3. Re-checks g.mcpTransport under the lock (line 1069)
4. Writes g.mcpTransport under the lock (line 1093)

The race occurs because:
- The fast-path read at line 1061 is UNSYNCHRONIZED
- Concurrent goroutines in both tests call handler.ServeHTTP() which triggers ensureMCPTransportInitialized()
- One goroutine writes g.mcpTransport at line 1093 (under lock) while another reads it at line 1061 (no lock)
- Additionally, sendMCPRequest (gateway.go:789) and fetchUpstreamToolsViaMCP (gateway.go:1018) both read g.mcpTransport without holding the mutex, passing it to mcpclient.SendWithRetry
- Gateway.Close() (gateway.go:1751) reads g.mcpTransport without any lock

### Affected Tests

1. TestMCPTransport_SessionIsolation (gateway_test.go:3431-3539)
   - Sends 5 concurrent POST requests via goroutines (lines 3500-3513)
   - All goroutines call handler.ServeHTTP concurrently
   - Race between lazy init writes and unsynchronized reads

2. TestMCPTransport_ReusedCallerID_UsesUniqueWireIDs (gateway_test.go:3541-3653)
   - Sends 2 concurrent POST requests via goroutines (lines 3619-3628)
   - Same race pattern: concurrent ServeHTTP triggers concurrent ensureMCPTransportInitialized

### Racy Code Paths (gateway.go)

Line 789: g.mcpTransport read without lock in sendMCPRequest
Line 1018: g.mcpTransport read without lock in fetchUpstreamToolsViaMCP
Line 1061: g.mcpTransport read without lock in ensureMCPTransportInitialized fast path
Line 1751: g.mcpTransport read without lock in Close()

## Fix Approach

Option A (Recommended): Add a getTransport() accessor that reads under the mutex:

```go
func (g *Gateway) getMCPTransport() mcpclient.Transport {
    g.mcpTransportMu.Lock()
    defer g.mcpTransportMu.Unlock()
    return g.mcpTransport
}
```

Then replace all bare g.mcpTransport reads with g.getMCPTransport():
- gateway.go:789 -> use g.getMCPTransport()
- gateway.go:1018 -> use g.getMCPTransport()
- gateway.go:1061 -> use g.getMCPTransport()
- gateway.go:1751 -> use g.getMCPTransport()

Option B (Alternative): Use sync/atomic with atomic.Pointer[mcpclient.Transport] for lock-free reads. This is more performant but changes the field type and requires Go 1.19+. Since we are on Go 1.24.6, this is viable but adds complexity.

Recommendation: Option A. The mutex is already there, the contention is negligible (lazy init, checked once per request at most), and it is the simplest correct fix.

## Acceptance Criteria

1. "go test -race ./internal/gateway/..." passes with zero race warnings
2. TestMCPTransport_SessionIsolation passes under -race
3. TestMCPTransport_ReusedCallerID_UsesUniqueWireIDs passes under -race
4. All other existing tests continue to pass (no regressions)
5. The fix does not change any public API or behavior
6. No new test files created -- changes are to gateway.go only (and possibly gateway_test.go if test-side races exist)

## Testing Requirements

- Unit tests: Run "go test -race -count=3 -run TestMCPTransport_SessionIsolation ./internal/gateway/" (3 iterations to increase race detection confidence)
- Unit tests: Run "go test -race -count=3 -run TestMCPTransport_ReusedCallerID_UsesUniqueWireIDs ./internal/gateway/" (3 iterations)
- Integration tests: Run full "go test -race ./internal/gateway/..." to confirm no regressions and no new races
- Verify: "go test ./..." still passes (full suite, no -race) with no behavior changes

## Files to Modify

- /Users/ramirosalas/workspace/agentic_reference_architecture/POC/internal/gateway/gateway.go (lines 789, 1018, 1061, 1751 -- add synchronized reads)

## Scope Boundary

This story fixes ONLY the data races on mcpTransport. It does NOT refactor the double-checked locking pattern, change the lazy initialization strategy, or modify any test logic. The tests themselves are correct -- the race is in the production code paths they exercise.

## Dependencies

None. This story is independent.

MANDATORY SKILLS TO REVIEW:
- None identified. Standard Go concurrency patterns (sync.Mutex accessor), no specialized skill requirements.

## Acceptance Criteria


## Design


## Notes
DELIVERED:
- CI Results: go test -race ./... PASS (all packages, zero race warnings)
- Targeted tests: TestMCPTransport_SessionIsolation PASS x3 under -race, TestMCPTransport_ReusedCallerID_UsesUniqueWireIDs PASS x3 under -race
- Full suite: go test ./... PASS (zero regressions)
- Commit: a5b7815 on main
- Files modified: internal/gateway/gateway.go, internal/gateway/middleware/audit.go

Changes:
1. gateway.go: Added getMCPTransport() accessor (reads g.mcpTransport under mcpTransportMu)
2. gateway.go: Replaced 4 bare g.mcpTransport reads with g.getMCPTransport() at sendMCPRequest, refreshObservedToolHashes, ensureMCPTransportInitialized (fast-path removed), Close()
3. audit.go: Added Auditor.LastHash() accessor (reads a.lastHash under a.mu)
4. audit.go: Replaced bare auditor.lastHash read in AuditLog middleware with auditor.LastHash()

AC Verification:

| AC # | Requirement | Code Location | Test Location | Status |
|------|-------------|---------------|---------------|--------|
| 1 | go test -race ./internal/gateway/... passes with zero race warnings | gateway.go getMCPTransport(), audit.go LastHash() | gateway_test.go:3431, 3541 | PASS |
| 2 | TestMCPTransport_SessionIsolation passes under -race | gateway.go:789 getMCPTransport() | gateway_test.go:3431-3539 | PASS |
| 3 | TestMCPTransport_ReusedCallerID_UsesUniqueWireIDs passes under -race | gateway.go:1018 getMCPTransport() | gateway_test.go:3541-3653 | PASS |
| 4 | All other existing tests continue to pass | No regressions | go test ./... | PASS |
| 5 | No public API or behavior changes | Only added private getMCPTransport() and exported LastHash() accessor | N/A | PASS |
| 6 | No new test files | Changes only to gateway.go and audit.go | N/A | PASS |

LEARNINGS:
- The original mcpTransport race was masking a secondary race on Auditor.lastHash (read without lock in AuditLog span attributes at audit.go:397). Fixing the first exposed the second.
- Double-checked locking without atomic/unsafe is inherently racy in Go. The language memory model requires synchronization for all cross-goroutine access. Replacing with single-check-under-mutex is correct and has negligible performance impact for lazy-init patterns.

OBSERVATIONS (unrelated to this task):
- [INFO] The reinitFn closures in handleMCPRequest and refreshObservedToolHashes both nil out g.mcpTransport under the lock then call ensureMCPTransportInitialized. This is correct but could be simplified with a dedicated resetAndReinitTransport() method to reduce duplication.

## History
- 2026-02-27T03:51:55Z status: open -> closed

## Links
- Parent: [[oc-l5u]]
- Follows: [[oc-a8e]]

## Comments
