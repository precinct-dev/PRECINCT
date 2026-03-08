---
id: oc-a8e
title: "Verify gorilla/websocket and gojsonschema dependency classification in go.mod"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T17:54:28Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:c6b31bc9ded9d23b1cf5e8ac749ddd85e5824ac49e46796eaebd389972211e1a"
closed_at: 2026-02-21T17:57:36Z
close_reason: "Verified: gorilla/websocket imported in openclaw_ws_adapter.go, gojsonschema imported in connector_authority.go. Both correctly direct. go mod tidy produces zero diff, go mod verify passes."
parent: oc-l5u
follows: [oc-fwc]
led_to: [oc-4a1]
---

## Description
## User Story

As a maintainer of the go.mod dependency list, I need to verify that gorilla/websocket and gojsonschema are correctly classified as direct dependencies (not indirect) so that the dependency graph accurately reflects actual import relationships in the codebase.

## Context

During GAP-3 work, "go mod tidy" promoted github.com/gorilla/websocket and github.com/xeipuuv/gojsonschema from indirect to direct dependencies. This was flagged as a cosmetic concern: if nothing in the codebase directly imports these packages, they should remain indirect. Investigation has now confirmed both ARE directly imported.

## Analysis Results

### gorilla/websocket (go.mod line 12): CORRECTLY DIRECT

Direct imports found in 4 files:
- internal/gateway/openclaw_ws_adapter.go:12 -> import "github.com/gorilla/websocket"
- internal/gateway/openclaw_ws_adapter_test.go:9 -> import "github.com/gorilla/websocket"
- cmd/openclaw-ws-smoke/main.go:13 -> import "github.com/gorilla/websocket"
- tests/integration/openclaw_ws_integration_local_test.go:16 -> import "github.com/gorilla/websocket"

Verdict: Production code (openclaw_ws_adapter.go) directly imports this package. It is CORRECTLY listed as a direct dependency.

### gojsonschema (go.mod line 18): CORRECTLY DIRECT

Direct imports found in 3 files:
- internal/gateway/connector_authority.go:15 -> import "github.com/xeipuuv/gojsonschema"
- internal/gateway/phase3_contract_catalog_test.go:16 -> import "github.com/xeipuuv/gojsonschema"
- tests/conformance/harness/harness.go:20 -> import "github.com/xeipuuv/gojsonschema"

Verdict: Production code (connector_authority.go) directly imports this package. It is CORRECTLY listed as a direct dependency.

## Resolution

Both packages are correctly classified as direct dependencies. The promotion from indirect to direct by "go mod tidy" was correct behavior -- it reflected actual direct imports that existed (or were added) in the codebase.

## Acceptance Criteria

1. Run "go mod tidy" and confirm go.mod does not change (already correct)
2. Run "go mod verify" and confirm all dependencies verify successfully
3. Confirm gorilla/websocket remains in the direct (first) require block of go.mod
4. Confirm gojsonschema remains in the direct (first) require block of go.mod
5. Document in a commit message or PR description that both packages were verified as correctly direct, with the import locations listed above

## Testing Requirements

- Unit tests: Not applicable (no code changes expected)
- Integration tests: Not technically feasible -- this is a dependency classification verification task, not a code change. The verification itself IS the test: "go mod tidy" should be a no-op, and "go mod verify" should pass.
- Verification commands:
  - "go mod tidy && git diff go.mod go.sum" (expect no diff)
  - "go mod verify" (expect "all modules verified")

## Files to Verify (NOT modify unless go mod tidy produces changes)

- /Users/ramirosalas/workspace/agentic_reference_architecture/POC/go.mod
- /Users/ramirosalas/workspace/agentic_reference_architecture/POC/go.sum

## Scope Boundary

This story verifies dependency classification ONLY. It does not upgrade, remove, or replace any dependencies. If "go mod tidy" produces changes, those changes should be committed, but no manual go.mod editing is expected.

## Dependencies

None. This story is independent.

MANDATORY SKILLS TO REVIEW:
- None identified. Standard Go module management (go mod tidy, go mod verify), no specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links
- Parent: [[oc-l5u]]
- Follows: [[oc-fwc]]
- Led to: [[oc-4a1]]

## Comments
