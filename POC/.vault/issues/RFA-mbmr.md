---
id: RFA-mbmr
title: "Extend WS handler with message.status, connector.register, and per-message SPIKE token resolution"
status: closed
priority: 1
type: task
parent: RFA-xynt
created_at: 2026-02-27T04:30:42Z
created_by: ramirosalas
updated_at: 2026-02-27T06:04:39Z
content_hash: "sha256:53184513cf1c162022c02c062c58d70e41b84385916f418d99cd03e4aca33e01"
blocked_by: [RFA-zxnh, RFA-np7t, RFA-1fui]
blocks: [RFA-yt63]
related: [RFA-cweb]
follows: [RFA-np7t, RFA-zxnh, RFA-cweb, RFA-ncf1]
labels: [accepted]
closed_at: 2026-02-27T06:04:39Z
close_reason: "Accepted: WS dispatch extended with message.status and connector.register. resolveSPIKERef refactored as reusable Adapter method, wired into handleMessageSend. All 9 new tests pass against real gateway+OPA with no mocks. Build clean."
led_to: [RFA-yt63, RFA-xzj6]
---

## Description
## User Story
As an OpenClaw agent connected via WebSocket, I need message.status and connector.register methods, plus robust per-message SPIKE token resolution, so that all messaging WS methods are available with proper per-message credential handling.

## Context
The walking skeleton (RFA-1fui) established the `message.send` WS method with basic per-message SPIKE token resolution. This story extends the WS handler with two additional methods and hardens the SPIKE token flow.

### CRITICAL ARCHITECTURE DECISION: Per-Message SPIKE Token Resolution

The HTTP middleware chain runs ONCE on the WS upgrade request. The `Authorization` header from `req.Header.Get("Authorization")` is the UPGRADE-TIME header, NOT a per-message credential. Each WS frame can carry a different SPIKE reference.

The walking skeleton established this pattern:
1. Each WS frame carries `params.auth_ref` containing a `spike://` reference
2. The adapter extracts this reference from the frame (NOT from the HTTP upgrade header)
3. The adapter calls the secret redeemer directly to resolve the SPIKE reference to an actual secret
4. The resolved secret is passed as `authHeader` to `ExecuteMessagingEgress`
5. If no `auth_ref` is in the frame params, the adapter falls back to the upgrade-time header (for backward compatibility)

This story EXTENDS that pattern to `message.status` (where applicable) and ensures connector.register does NOT use SPIKE resolution (operator-only, no external egress).

### Per-Message SPIKE Resolution Implementation Detail

The adapter must implement a helper that mirrors the token substitution logic from `middleware/hooks.go`:

```go
// resolveSPIKERef resolves a SPIKE token reference for per-message egress.
// This is the WS-frame analog of the middleware TokenSubstitution step 13.
// The middleware runs once at upgrade time; this runs per WS frame.
//
// Flow:
// 1. Parse spike:// URI from frame.Params["auth_ref"]
// 2. Call redeemer.RedeemSecret(ctx, token) to get actual secret
// 3. Return the resolved secret value as the Authorization header value
// 4. If auth_ref is empty, return fallbackAuth (the upgrade-time header)
func (a *Adapter) resolveSPIKERef(ctx context.Context, authRef string, fallbackAuth string) (string, error) {
    if strings.TrimSpace(authRef) == "" {
        return fallbackAuth, nil
    }
    // Check if it looks like a SPIKE reference
    if !strings.HasPrefix(authRef, "spike://") {
        // Not a SPIKE ref, use as-is (e.g., raw Bearer token)
        return authRef, nil
    }
    // Parse the SPIKE token
    token, err := middleware.ParseSPIKEToken(authRef)
    if err != nil {
        return "", fmt.Errorf("parse SPIKE token from auth_ref: %w", err)
    }
    // Validate expiry
    if err := middleware.ValidateTokenExpiry(token); err != nil {
        return "", fmt.Errorf("SPIKE token expired: %w", err)
    }
    // Redeem via the configured redeemer (POC or Nexus)
    secret, err := a.redeemer.RedeemSecret(ctx, token)
    if err != nil {
        return "", fmt.Errorf("redeem SPIKE token: %w", err)
    }
    return secret.Value, nil
}
```

The adapter needs access to the redeemer. This is available via the gateway services -- add a `SecretRedeemer() middleware.SecretRedeemer` method to PortGatewayServices, or pass the redeemer at adapter construction time.

## What to Build

### 1. Add `message.status` Method (`ports/openclaw/ws_handler.go`)

In the switch statement, add:
```go
case "message.status":
    if !wsAllowed(session, frame.Method) {
        // ... forbidden response ...
        continue
    }
    a.handleMessageStatus(req, session, frame, conn, decisionID, traceID)
```

### 2. Add `connector.register` Method (`ports/openclaw/ws_handler.go`)

```go
case "connector.register":
    a.handleConnectorRegister(req, session, frame, conn, decisionID, traceID)
```

### 3. Update `wsAllowed` function

```go
case "message.status":
    if session.Role == "operator" { return true }
    _, ok := session.Scopes["tools.messaging.status"]
    return ok
case "connector.register":
    return session.Role == "operator"
```

### 4. Implement `handleMessageStatus` (`ports/openclaw/messaging_egress.go`)

Returns delivery status for a given platform/message_id. For POC, returns simulated "delivered" status.

### 5. Implement `handleConnectorRegister` (`ports/openclaw/messaging_egress.go`)

Operator-only. Returns connector registration acknowledgment. Does NOT use SPIKE resolution (no external egress).

### 6. Update Connect Hello Methods List

In `handleWSConnect`, add new methods to the methods list when scopes allow:
```go
if wsAllowed(*session, "message.status") {
    methods = append(methods, "message.status")
}
if wsAllowed(*session, "connector.register") {
    methods = append(methods, "connector.register")
}
```

### 7. Harden Per-Message SPIKE Resolution

The walking skeleton established basic SPIKE resolution in `handleMessageSend`. This story:
- Extracts the `resolveSPIKERef` helper into a reusable method on the Adapter
- Ensures the adapter has access to the secret redeemer
- Adds error handling for expired tokens, invalid SPIKE URIs, and redeemer failures
- Logs SPIKE resolution events for audit trail

## Acceptance Criteria
1. WS method dispatch handles `message.status` and `connector.register`
2. `message.status` returns delivery status for a given platform/message_id
3. `connector.register` is operator-only and returns connector registration acknowledgment
4. `message.send` resolves SPIKE token from `frame.Params["auth_ref"]` (per-message), NOT from HTTP upgrade header
5. `resolveSPIKERef` helper: parses spike:// URI, validates expiry, calls redeemer, returns secret value
6. `resolveSPIKERef` falls back to upgrade-time header when `auth_ref` is empty
7. `resolveSPIKERef` passes non-SPIKE values through unchanged (e.g., raw Bearer tokens)
8. Connect hello response includes `message.status` and `connector.register` in features.methods when scopes allow
9. `go build ./...` succeeds
10. Unit tests in `ports/openclaw/messaging_egress_test.go` cover: message.status, connector.register, SPIKE resolution (happy path, expired token, empty auth_ref fallback, non-SPIKE passthrough)

## Technical Notes
- The PlaneRequestV2 and RunEnvelope types are in `internal/gateway/types.go`
- Existing patterns: ws_handler.go handleWSConnect (line 169-251), devices.ping handler (line 145-161)
- The gateway services interface is accessed via `a.gw` (see adapter.go line 14)
- SPIKE token types: `middleware.SPIKEToken`, `middleware.ParseSPIKEToken`, `middleware.ValidateTokenExpiry` in hooks.go / spike_token.go
- The POCSecretRedeemer returns `secret-value-for-<ref>` (hooks.go line 332)
- Per-message resolution means each WS frame can use a DIFFERENT SPIKE reference (e.g., different API key per platform)

## Testing Requirements
- Unit tests: test WS frame -> response for message.status and connector.register with mock gateway services
- Unit tests: test resolveSPIKERef with mock redeemer (happy path, expired, empty, non-SPIKE)
- Integration tests are covered by story RFA-yt63

## Scope Boundary
This story extends WS handler methods and hardens SPIKE resolution. The walking skeleton (RFA-1fui) established message.send and basic SPIKE flow. Gateway egress hardening (RFA-zxnh), config/policy (RFA-np7t), simulator extensions (RFA-ncf1) are handled by sibling stories.

## Dependencies
- Requires RFA-1fui (walking skeleton) -- message.send method and basic SPIKE resolution established
- Requires RFA-zxnh (hardened egress) -- ExecuteMessagingEgress supports all platforms
- Requires RFA-np7t (config) -- messaging_status tool registered in OPA

## MANDATORY SKILLS TO REVIEW
- None identified. Follows existing WS handler patterns in ws_handler.go. SPIKE token patterns are established in hooks.go.

## History
- 2026-02-27T06:04:39Z status: in_progress -> closed

## Links
- Parent: [[RFA-xynt]]
- Blocks: [[RFA-yt63]]
- Blocked by: [[RFA-zxnh]], [[RFA-np7t]], [[RFA-1fui]]
- Related: [[RFA-cweb]]
- Follows: [[RFA-np7t]], [[RFA-zxnh]], [[RFA-cweb]], [[RFA-ncf1]]
- Led to: [[RFA-yt63]], [[RFA-xzj6]]

## Comments

### 2026-02-27T06:00:27Z ramirosalas
COMPLETED: message.status dispatch, connector.register dispatch, wsAllowed scoping, connect hello methods, resolveSPIKERef helper, handleMessageStatus, handleConnectorRegister, handleMessageSend refactored. 9 new unit tests all pass. go build ./... clean. Commit: c45379f
