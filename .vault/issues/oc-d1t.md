---
id: oc-d1t
title: "GAP-5: Delete empty Phase 3 engine scaffolding"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T03:20:51Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:46Z
content_hash: "sha256:e264a118c88174bebe1b7e42915e1acbce92f9fa4cd570901ee2cadf884497b5"
closed_at: 2026-02-21T03:43:22Z
close_reason: "3 empty engine structs and all references deleted. Loop and tool policy engines preserved. 14/14 packages pass."
blocked_by: [oc-kxh]
---

## Description
WHAT: Surgically remove three empty engine structs (ingressPlanePolicyEngine, contextPlanePolicyEngine, rlmGovernanceEngine) and their constructors from internal/gateway/phase3_plane_stubs.go. Remove corresponding field references from internal/gateway/gateway.go. PRESERVE all real engines in the same file (loopPlanePolicyEngine, toolPlanePolicyEngine) and all their helper types/functions.

WHY: The file phase3_plane_stubs.go is 804 lines. Three of the engines defined there are empty structs that evaluate nothing -- they are premature architecture for engines that were never implemented. Their presence signals 'unfinished work' to a code reviewer. Git has history; deleting them loses nothing. However, the same file contains two REAL engines (loopPlanePolicyEngine with full breach evaluation logic, toolPlanePolicyEngine with capability registry and action policy evaluation) that MUST be preserved.

HOW:
1. In internal/gateway/phase3_plane_stubs.go:
   - DELETE: ingressPlanePolicyEngine struct (line 19) and newIngressPlanePolicyEngine() (lines 21-23)
   - DELETE: contextPlanePolicyEngine struct (line 25) and newContextPlanePolicyEngine() (lines 27-29)
   - DELETE: rlmGovernanceEngine struct (line 800) and newRLMGovernanceEngine() (lines 802-804)
   - KEEP: Everything else -- loopPlanePolicyEngine (lines 37-804 region covering loop and tool engines), all loop* types, all tool* types, all helper functions

2. In internal/gateway/gateway.go:
   - DELETE field: ingressPolicy *ingressPlanePolicyEngine (line 60)
   - DELETE field: contextPolicy *contextPlanePolicyEngine (line 61)
   - DELETE field: rlmPolicy *rlmGovernanceEngine (line 64)
   - Search for ALL references to these three fields and their constructors throughout internal/gateway/*.go and remove them
   - KEEP: modelPlanePolicy, loopPolicy, toolPolicy fields (lines 59, 62, 63)

3. Verify compilation: 'go build ./...' must pass
4. Verify tests: 'go test ./...' must pass with zero failures

TECHNICAL CONTEXT:
- The Gateway struct in gateway.go holds pointers to these empty engines at lines 60-61, 64
- The constructors are called somewhere in the gateway initialization code -- search for newIngressPlanePolicyEngine(), newContextPlanePolicyEngine(), newRLMGovernanceEngine() and remove those calls
- The real engines (modelPlanePolicyEngine in phase3_model_plane.go, loopPlanePolicyEngine and toolPlanePolicyEngine in phase3_plane_stubs.go) have extensive test coverage and must not be touched

FILES TO MODIFY:
- MODIFY: internal/gateway/phase3_plane_stubs.go (delete 3 empty structs + constructors)
- MODIFY: internal/gateway/gateway.go (delete 3 fields + all references)
- POSSIBLY MODIFY: other files in internal/gateway/ that reference the deleted types

TESTING REQUIREMENTS:
- Unit test: 'go build ./...' compiles cleanly
- Integration test: 'go test -race ./...' passes with zero failures. Specifically verify that tests in internal/gateway/phase3_plane_stubs_test.go (if it exists), internal/gateway/gateway_test.go, and tests/integration/walking_skeleton_phase3_test.go still pass.
- Run the full test suite and compare test count before/after -- count should not decrease (no test files accidentally deleted)

MANDATORY SKILLS TO REVIEW:
- None identified. Standard Go refactoring, no specialized skill requirements.

## Acceptance Criteria
AC1: ingressPlanePolicyEngine, contextPlanePolicyEngine, rlmGovernanceEngine types and constructors deleted from phase3_plane_stubs.go
AC2: Corresponding fields and all references deleted from gateway.go and any other files in internal/gateway/
AC3: loopPlanePolicyEngine and toolPlanePolicyEngine remain intact with all their types, methods, and helpers
AC4: 'go build ./...' compiles with zero errors
AC5: 'go test -race ./...' passes with zero failures
AC6: Test function count is unchanged (no accidental test deletion)

## Design


## Notes


## History
- 2026-03-08T02:10:22Z dep_added: blocked_by oc-kxh

## Links
- Blocked by: [[oc-kxh]]

## Comments
