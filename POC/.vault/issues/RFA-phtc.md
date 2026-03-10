---
id: RFA-phtc
title: "Go SDK CallModelChat can bypass PRECINCT by posting to absolute endpoints"
status: closed
priority: 0
type: bug
labels: [release-sanity, security, sdk, accepted]
parent: RFA-rlpe
created_at: 2026-03-10T04:55:56Z
created_by: ramirosalas
updated_at: 2026-03-10T13:48:00Z
content_hash: "sha256:ed572970391537845bde6de8a94c995075c55c6e60fc3acedec436a652db9551"
follows: [RFA-aszr, RFA-x3ny, RFA-odey, RFA-k7l5]
closed_at: 2026-03-10T13:48:00Z
close_reason: "Accepted after PM review against final Makefile release validation."
---

## Description
## Context (Embedded)
- Problem: The Go SDK helper that claims to call the gateway model egress endpoint will send requests directly to any absolute `http://` or `https://` endpoint.
- Evidence:
  - Helper comment says it sends through the gateway model egress endpoint: sdk/go/mcpgateway/client.go:128.
  - Absolute endpoints are preserved and used directly: sdk/go/mcpgateway/client.go:130.
- Impact: Callers can accidentally or intentionally bypass gateway mediation while still using the gateway SDK API.

## Acceptance Criteria
1. `CallModelChat` cannot silently bypass gateway mediation via absolute endpoints.
2. If direct egress remains supported, it is exposed through a separate explicit API that cannot be mistaken for mediated egress.
3. Tests cover both mediated default behavior and rejection or explicit separation of bypass behavior.

## Testing Requirements
- Add unit tests for relative endpoint routing and absolute endpoint handling.
- Update docs/examples to reflect the final contract unambiguously.

## nd_contract
status: new

### evidence
- 2026-03-10 sanity review of Go SDK model helper.

### proof
- [ ] AC #1: Absolute endpoint bypass is removed or explicitly separated.
- [ ] AC #2: API contract clearly distinguishes mediated vs direct behavior.
- [ ] AC #3: Tests cover the endpoint handling rules.

## Acceptance Criteria


## Design


## Notes
## nd_contract
status: delivered

### evidence
- Final authoritative contract for 2026-03-10 Go SDK scope: CallModelChat absolute URLs rejected, relative routing covered, README updated to mediated-only contract.
- Validation: go test ./... -count=1 -> ok github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway 2.155s
- Validation: go test ./mcpgateway -run 'TestCallModelChat_(HeadersAndEndpoint|RelativeEndpointsStayOnGateway|DenialParsesGatewayError|RejectsAbsoluteEndpoints)' -count=1 -> ok github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway 1.899s

### proof
- [x] AC #1: CallModelChat rejects absolute endpoints instead of silently bypassing the gateway.
- [x] AC #2: The Go SDK contract is explicitly mediated-only in code comments and README docs.
- [x] AC #3: Tests cover default mediated behavior, relative endpoint routing, denial parsing, and absolute endpoint rejection.

## Implementation Evidence (DELIVERED)

### CI/Test Results
- Commands run:
  - go test ./... -count=1
  - go test ./mcpgateway -run 'TestCallModelChat_(HeadersAndEndpoint|RelativeEndpointsStayOnGateway|DenialParsesGatewayError|RejectsAbsoluteEndpoints)' -count=1
  - rg -n 'TODO|NotImplementedError|panic\(\"todo\"\)|unimplemented!|raise NotImplementedError' sdk/go/mcpgateway/client.go sdk/go/mcpgateway/client_test.go sdk/go/README.md
- Summary: Go SDK package PASS; focused model-chat contract tests PASS; stub/TODO scan returned no matches.
- Key output:
  - go test ./... -count=1 -> ok github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway 2.155s
  - go test ./mcpgateway -run 'TestCallModelChat_(HeadersAndEndpoint|RelativeEndpointsStayOnGateway|DenialParsesGatewayError|RejectsAbsoluteEndpoints)' -count=1 -> ok github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway 1.899s

### AC Verification
| AC # | Requirement | Code Location | Test / Doc Location | Status |
|------|-------------|---------------|---------------------|--------|
| 1 | CallModelChat cannot silently bypass gateway mediation via absolute endpoints | sdk/go/mcpgateway/client.go | sdk/go/mcpgateway/client_test.go (`TestCallModelChat_RejectsAbsoluteEndpoints`) | PASS |
| 2 | The contract clearly distinguishes mediated behavior from any direct egress | sdk/go/mcpgateway/client.go | sdk/go/README.md (`CallModelChat` section states gateway-relative only and no direct helper) | PASS |
| 3 | Tests cover mediated default behavior plus endpoint handling rules | sdk/go/mcpgateway/client_test.go | sdk/go/mcpgateway/client_test.go (`HeadersAndEndpoint`, `RelativeEndpointsStayOnGateway`, `DenialParsesGatewayError`, `RejectsAbsoluteEndpoints`) | PASS |

## nd_contract
status: delivered

### evidence
- Strengthened Go SDK documentation so CallModelChat is explicitly described as mediated gateway egress only, with no direct-to-provider helper in the SDK.
- Added relative-endpoint routing coverage for both leading-slash and bare relative paths so the story verifies mediated custom routing as well as absolute-URL rejection.
- Validation commands and outputs captured above; no new bug discovered within the scoped Go SDK contract work.

### proof
- [x] AC #1: Absolute endpoint bypass is rejected by CallModelChat.
- [x] AC #2: The API contract now makes mediated-only behavior explicit in code comments and Go SDK docs.
- [x] AC #3: Tests cover default mediated routing, relative endpoint routing, gateway denial parsing, and absolute endpoint rejection.

## nd_contract
status: in_progress

### evidence
- 2026-03-10 developer resumed implementation for Go SDK model-chat egress contract from existing in-flight SDK changes.
- Scope constrained to , , and directly related Go SDK docs/examples.

### proof
- [ ] AC #1: Absolute endpoint bypass is removed or explicitly separated.
- [ ] AC #2: API contract clearly distinguishes mediated vs direct behavior.
- [ ] AC #3: Tests cover the endpoint handling rules.

## nd_contract
status: delivered

### evidence
- `sdk/go/mcpgateway/client.go` now rejects absolute model endpoints with `CallModelChat only supports gateway-relative endpoints; absolute endpoints are not allowed`.
- `sdk/go/mcpgateway/client_test.go` includes `TestCallModelChat_RejectsAbsoluteEndpoints` alongside the normal mediated success/error cases.
- `go test ./mcpgateway -run 'TestCallModelChat_(HeadersAndEndpoint|DenialParsesGatewayError|RejectsAbsoluteEndpoints)' -count=1` (run from `sdk/go`) -> PASS (`ok github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway 0.324s`).

### proof
- [x] AC #1: `CallModelChat` can no longer silently bypass mediated egress via absolute URLs.
- [x] AC #2: The helper contract is now unambiguous: mediated gateway-relative paths only.
- [x] AC #3: Go SDK tests cover both the normal mediated route and the absolute-endpoint rejection path.

## nd_contract
status: delivered

### evidence
- Verified `sdk/go/mcpgateway/client.go` now rejects absolute `http://` and `https://` endpoints inside `CallModelChat`, preserving gateway-mediated egress only.
- `go test ./... -run "TestCallModelChat|TestNewClient" -count=1` from `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/sdk/go` -> PASS (`ok   github.com/RamXX/agentic_reference_architecture/POC/sdk/go/mcpgateway ...`).
- Existing Go SDK tests include `TestCallModelChat_RejectsAbsoluteEndpoints` and the mediated success path.

### proof
- [x] AC #1: `CallModelChat` no longer permits silent bypass through absolute endpoints.
- [x] AC #2: The mediated helper contract is explicit: gateway-relative endpoints only.
- [x] AC #3: Go SDK tests cover mediated success and absolute-endpoint rejection.

## History
- 2026-03-10T13:48:00Z status: in_progress -> closed

## Links
- Parent: [[RFA-rlpe]]
- Follows: [[RFA-aszr]], [[RFA-x3ny]], [[RFA-odey]], [[RFA-k7l5]]

## Comments

## PM Acceptance
- Reviewed the delivered proof for RFA-phtc against the final Makefile release run.
- Acceptance basis:
  - `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
  - `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
  - `make story-evidence-validate STORY_ID=RFA-phtc` -> PASS.

## nd_contract
status: accepted

### evidence
- PM review confirmed the story's recorded delivery evidence remains valid after the final Makefile release validation run.
- `make test > /tmp/make-test-final5.log 2>&1` -> PASS.
- `/tmp/make-demo-final3.log` -> `ALL DEMOS PASSED (compose)`, `ALL DEMOS PASSED (k8s)`, `ALL CYCLES PASSED`.
- `make story-evidence-validate STORY_ID=RFA-phtc` -> PASS.

### proof
- [x] PM acceptance: the recorded delivery proof satisfies the story acceptance criteria and remains valid in the final release run.
