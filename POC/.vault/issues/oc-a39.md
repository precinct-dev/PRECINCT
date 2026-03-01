---
id: oc-a39
title: "Align WS adapter node-role connect policy with upstream device-identity requirement"
status: closed
priority: 1
type: task
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T19:56:54Z
created_by: ramirosalas
updated_at: 2026-02-27T03:51:55Z
content_hash: "sha256:e230b30db6e9e3436b55419fc56f40c894b123862ffa4efb7b939f6aa88c9eb8"
closed_at: 2026-02-21T20:02:50Z
close_reason: "Enforced device-identity requirement for node-role WS connects. Added reasonWSDeviceRequired constant and early guard in handleOpenClawWSConnect. All 5 AC verified: node-no-device rejected with WS_DEVICE_REQUIRED/403, node-with-device succeeds, operator-without-device succeeds, operator-with-device succeeds, audit log records deny. Full test suite passes with -race."
blocks: [oc-0bl, oc-b9w]
parent: oc-6bq
led_to: [oc-0bl]
---

## Description
## User Story

As a gateway operator, I need the OpenClaw WS adapter to enforce the same device-identity requirement for node-role connections that upstream OpenClaw now mandates, so that the gateway wrapper does not accept connections that the real OpenClaw server would reject.

## Context and Business Value

OpenClaw commit ddcb2d79b ("fix(gateway): block node role when device identity is missing") changed the upstream contract: node-role WS connections now REQUIRE device identity during the connect handshake. Previously, operator-role connections could omit device identity with shared-secret auth, but node-role could not. Our WS adapter in `openclaw_ws_adapter.go` currently allows node-role connect without device identity -- this is a contract drift that would cause the gateway to accept connections that the real OpenClaw server would reject.

Additionally, commit 51149fcaf extracted connect policy into `connect-policy.ts` with `evaluateMissingDeviceIdentity()` and role policy into `role-policy.ts` with `roleCanSkipDeviceIdentity()` (only operator+sharedAuth=true can skip).

## What Changed Upstream

1. `role-policy.ts` -- `roleCanSkipDeviceIdentity(role, sharedAuthOk)` returns true ONLY for `role === "operator" && sharedAuthOk`.
2. `connect-policy.ts` -- `evaluateMissingDeviceIdentity()` returns `reject-device-required` for node role without device identity.
3. Protocol doc updated: "All WS clients must include device identity during connect (operator + node). Control UI can omit it only when `gateway.controlUi.dangerouslyDisableDeviceAuth` is enabled for break-glass use."

## Implementation

All changes are in the adapter layer ONLY. No core gateway changes.

### File: `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/internal/gateway/openclaw_ws_adapter.go`

In `handleOpenClawWSConnect()` (line ~226), after validating `role` is "operator" or "node", add device-identity enforcement for node role:

```go
// After role validation and before setting session.Connected:
if role == "node" {
    device, hasDevice := frame.Params["device"].(map[string]any)
    deviceID := ""
    if hasDevice {
        deviceID = strings.TrimSpace(getStringAttr(device, "id", ""))
    }
    if deviceID == "" {
        g.writeOpenClawWSFailure(conn, frame.ID, http.StatusForbidden, reasonWSAuthInvalid, "node role requires device identity", decisionID, traceID)
        g.logOpenClawWSDecision(req, *session, frame.Method, DecisionDeny, reasonWSAuthInvalid, decisionID, traceID, http.StatusForbidden)
        return nil
    }
}
```

### File: `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/internal/gateway/openclaw_ws_adapter.go`

Add a new reason code constant:
```go
const reasonWSDeviceRequired ReasonCode = "WS_DEVICE_REQUIRED"
```
Use this instead of `reasonWSAuthInvalid` for the node device-identity check.

## Acceptance Criteria

1. [AC1] Node-role connect WITHOUT device identity in params returns `ok:false` with reason_code `WS_DEVICE_REQUIRED` and HTTP status 403.
2. [AC2] Node-role connect WITH valid device identity (params.device.id is non-empty and params.auth.token is present) succeeds as before.
3. [AC3] Operator-role connect WITHOUT device identity continues to succeed (backward compatible).
4. [AC4] Operator-role connect WITH device identity continues to succeed.
5. [AC5] Audit log records the deny decision with action `openclaw.ws.connect` and reason_code `WS_DEVICE_REQUIRED`.

## Testing Requirements
### Unit tests (mocks OK)

- Add test case to `TestOpenClawWSGatewayProtocol_AuthzAndMalformedDenied` in `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/internal/gateway/openclaw_ws_adapter_test.go` for node-role-without-device-identity deny.

### Integration tests (MANDATORY, no mocks)

- Add test case to `TestGatewayAuthz_OpenClawWSDenyMatrix_Integration` in `/Users/ramirosalas/workspace/agentic_reference_architecture/POC/tests/integration/openclaw_ws_integration_local_test.go`:
  - "node without device identity denied" subtest.
  - "node with device identity allowed" subtest (device.id + auth.token).
- Verify audit log contains `WS_DEVICE_REQUIRED` reason code.

### Test commands

```bash
go test -v -run TestOpenClawWSGatewayProtocol ./internal/gateway/...
go test -v -run TestGatewayAuthz_OpenClawWSDenyMatrix ./tests/integration/...
go test -v -run TestAuditOpenClawWSCorrelation ./tests/integration/...
```

## Scope Boundary

Scope: WS adapter only. Files modified:
- `internal/gateway/openclaw_ws_adapter.go` -- add device-identity check for node role, add reason code
- `internal/gateway/openclaw_ws_adapter_test.go` -- new unit test subcase (file may need creation if subtests live elsewhere)
- `tests/integration/openclaw_ws_integration_local_test.go` -- new integration test subcases
No changes to: core gateway, middleware, policy engine, HTTP adapter.

## Dependencies

None -- this is the first story in the epic.

MANDATORY SKILLS TO REVIEW:
- None identified. Standard Go patterns, WebSocket protocol handling. No specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-02-27T03:51:55Z dep_added: blocks oc-b9w

## Links
- Parent: [[oc-6bq]]
- Blocks: [[oc-0bl]], [[oc-b9w]]
- Led to: [[oc-0bl]]

## Comments
