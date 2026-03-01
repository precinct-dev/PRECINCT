---
id: RFA-ajf6
title: "Register SPIKE secret references for messaging platform API keys"
status: closed
priority: 1
type: task
parent: RFA-xynt
created_at: 2026-02-27T04:32:09Z
created_by: ramirosalas
updated_at: 2026-02-27T06:07:22Z
content_hash: "sha256:9fdc072fcbfaf78fe6c4e77fda36e27390bdde41a358fe5d68b875c9da4d3dba"
blocked_by: [RFA-ncf1, RFA-zxnh, RFA-1fui]
blocks: [RFA-yt63]
follows: [RFA-ncf1, RFA-cweb]
labels: [accepted]
closed_at: 2026-02-27T06:07:22Z
close_reason: "Accepted: SPIKE secret seeder in docker-compose.yml seeds whatsapp-api-key, telegram-bot-token, slack-bot-token (lines 341-343). Unit tests for all three platform SPIKE references pass (3/3 subtests). POCSecretRedeemer generic pattern verified. Simulator accepts any non-empty Bearer token. PortGatewayServices exposes RedeemSPIKESecret. go build ./... clean. Integration tests deferred to RFA-yt63 per story scope."
led_to: [RFA-yt63, RFA-xzj6]
---

## Description
## User Story
As the gateway operator, I need SPIKE secret references for WhatsApp, Telegram, and Slack API keys seeded and the gateway configured so that per-message SPIKE token resolution in the WS handler can resolve platform credentials before outbound messaging HTTP POSTs.

## Context
The walking skeleton (RFA-1fui) established the basic per-message SPIKE resolution pattern: the WS handler extracts `spike://` references from `frame.Params["auth_ref"]` and calls the redeemer. This story seeds the actual SPIKE secrets and ensures the end-to-end flow works for all three platforms.

### ARCHITECTURE DECISION: Per-Message SPIKE Resolution

The middleware TokenSubstitution (step 13) runs ONCE at WS upgrade time. It cannot substitute per-message credentials because the middleware chain processes the HTTP upgrade request, not individual WS frames.

For WS messaging, SPIKE token resolution happens in the port adapter:
1. WS frame `params.auth_ref` contains `spike://whatsapp-api-key?scope=tools.messaging.send&exp=<future>&iss=<now>`
2. Adapter calls `resolveSPIKERef()` which parses the token and calls `redeemer.RedeemSecret()`
3. Resolved secret value becomes the Authorization header for `ExecuteMessagingEgress`
4. Each WS frame can carry a DIFFERENT SPIKE reference (e.g., per-platform keys)

The existing `tokenSubstitutionHeaders` list in hooks.go (line 274-282) is NOT used for per-message resolution. The adapter calls the redeemer directly.

## What to Build

### 1. Add SPIKE Secret References to Seeder Script

Update `scripts/seed-spike-secrets.sh` to seed three new secrets (if using SPIKE Nexus compose mode):

```bash
# Messaging platform API keys (RFA-xynt)
spike secret put "whatsapp-api-key" value="Bearer whatsapp-api-key-placeholder"
spike secret put "telegram-bot-token" value="bot:telegram-bot-token-placeholder"
spike secret put "slack-bot-token" value="Bearer xoxb-slack-bot-token-placeholder"
```

### 2. Document SPIKE Reference Format for Messaging

The SPIKE token format is `spike://<ref>?scope=<scope>&exp=<unix_ts>&iss=<unix_ts>`. For messaging (passed in WS frame `params.auth_ref`):

- WhatsApp: `spike://whatsapp-api-key?scope=tools.messaging.send&exp=<future>&iss=<now>`
- Telegram: `spike://telegram-bot-token?scope=tools.messaging.send&exp=<future>&iss=<now>`
- Slack: `spike://slack-bot-token?scope=tools.messaging.send&exp=<future>&iss=<now>`

### 3. Update POCSecretRedeemer Mock Values Alignment

The POCSecretRedeemer (hooks.go line 332) returns `secret-value-for-<ref>`. For messaging:
- `spike://whatsapp-api-key` -> `secret-value-for-whatsapp-api-key`
- `spike://telegram-bot-token` -> `secret-value-for-telegram-bot-token`
- `spike://slack-bot-token` -> `secret-value-for-slack-bot-token`

The messaging simulator (extended by RFA-ncf1) must accept these mock values as valid tokens. Confirm the simulator auth validation accepts any non-empty Bearer token (already established by walking skeleton for WhatsApp; RFA-ncf1 extends to Telegram/Slack).

### 4. Ensure Adapter Has Redeemer Access

The adapter must have access to the SecretRedeemer for per-message resolution. Verify the adapter constructor receives the redeemer, or that it is accessible via `a.gw` gateway services interface.

If PortGatewayServices does not expose the redeemer, add:
```go
// In port.go PortGatewayServices interface:
SecretRedeemer() middleware.SecretRedeemer
```

And in port_services.go:
```go
func (g *Gateway) SecretRedeemer() middleware.SecretRedeemer {
    return g.secretRedeemer
}
```

## Acceptance Criteria
1. `scripts/seed-spike-secrets.sh` includes seed commands for `whatsapp-api-key`, `telegram-bot-token`, `slack-bot-token`
2. When a SPIKE reference `spike://whatsapp-api-key?scope=tools.messaging.send&...` appears in WS frame `params.auth_ref`, the adapter resolves it to `secret-value-for-whatsapp-api-key` via the redeemer
3. The adapter has access to the SecretRedeemer (either via gateway services interface or constructor injection)
4. The messaging simulator accepts POC redeemer token format (`secret-value-for-<ref>`) as valid auth
5. All three platform SPIKE references resolve correctly in the per-message flow
6. `go build ./...` succeeds after changes

## Technical Notes
- SPIKE token format: `internal/gateway/middleware/token_types.go` (ParseSPIKEToken, FindSPIKETokens)
- Per-message resolution flow: adapter calls `middleware.ParseSPIKEToken()` -> `middleware.ValidateTokenExpiry()` -> `redeemer.RedeemSecret()` -> uses `secret.Value` as authHeader
- POCSecretRedeemer: hooks.go line 288-339
- SPIKENexusRedeemer (production): makes mTLS calls to `https://spike-nexus:8443/api/v1/redeem`
- For docker-compose mode, `scripts/seed-spike-secrets.sh` is called by the spike-secret-seeder service

## Testing Requirements
- Unit tests: verify adapter resolves SPIKE refs correctly for all three platforms using mock redeemer
- Integration tests are covered by story RFA-yt63

## Scope Boundary
This story wires SPIKE secrets and redeemer access for messaging. The per-message resolution pattern was established by the walking skeleton (RFA-1fui). Simulator extensions (RFA-ncf1), egress hardening (RFA-zxnh), and integration tests (RFA-yt63) are sibling stories.

## Dependencies
- Requires RFA-1fui (walking skeleton) -- per-message SPIKE pattern established
- Requires RFA-ncf1 (simulator) -- simulator must accept POC redeemer tokens for all platforms
- Requires RFA-zxnh (egress) -- egress passes Authorization header with resolved secret

## MANDATORY SKILLS TO REVIEW
- None identified. SPIKE token patterns are well-established in the codebase.

## History
- 2026-02-27T06:07:22Z status: in_progress -> closed

## Links
- Parent: [[RFA-xynt]]
- Blocks: [[RFA-yt63]]
- Blocked by: [[RFA-ncf1]], [[RFA-zxnh]], [[RFA-1fui]]
- Follows: [[RFA-ncf1]], [[RFA-cweb]]
- Led to: [[RFA-yt63]], [[RFA-xzj6]]

## Comments

### 2026-02-27T06:02:19Z ramirosalas
COMPLETED: All ACs verified and committed. Commit 9181d79. SPIKE seeder updated in docker-compose.yml with whatsapp-api-key, telegram-bot-token, slack-bot-token. Existing unit test (TestOpenClawWS_MessageSend_AllPlatformSPIKEReferences) already covers all three platform SPIKE references from prior RFA-mbmr commit. POCSecretRedeemer, messaging sim, and port interface all verified as compatible -- no code changes needed.
