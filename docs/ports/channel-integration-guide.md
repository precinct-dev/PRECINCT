# Channel Integration Guide

## Purpose

Explain what messaging channels PRECINCT supports today through its port adapter model, what happens when an unsupported channel is used, and how to extend support for new channels -- with or without source code changes.

---

## Current Channel Support

The gateway mediates messaging through **port adapters** registered at startup. Each adapter handles platform-specific webhook ingress, payload normalization, and messaging egress for its supported channels.

### OpenClaw Port (`ports/openclaw/`)

The OpenClaw adapter supports three inbound messaging channels via webhook receivers:

| Channel | Webhook Path | Egress Endpoint | Status |
|---------|-------------|-----------------|--------|
| WhatsApp | `POST /openclaw/webhooks/whatsapp` | `graph.facebook.com/v17.0/messages` | Supported |
| Telegram | `POST /openclaw/webhooks/telegram` | `api.telegram.org/bot{token}/sendMessage` | Supported |
| Slack | `POST /openclaw/webhooks/slack` | `slack.com/api/chat.postMessage` | Supported |

Each channel gets a SPIFFE identity for audit: `spiffe://poc.local/webhooks/{platform}`.

### Standalone Port Adapters

| Port | Location | Channel |
|------|----------|---------|
| Discord | `ports/discord/` | Discord webhooks and interactions |
| Email | `ports/email/` | Email (SMTP/IMAP via gateway) |

### What Happens with Unsupported Channels

OpenClaw itself supports many more channels (LINE, Messenger, Signal, Matrix, custom webhooks, etc.). If OpenClaw is configured to use a channel that the gateway does not have a webhook receiver for:

1. **Inbound webhooks** for the unsupported channel will not reach the gateway (no registered route). The webhook delivery will fail with a 404 or fall through to the MCP handler and receive a 403.
2. **Outbound messages** via WebSocket `message.send` will attempt to resolve the platform endpoint. If no `MESSAGING_PLATFORM_ENDPOINT_{PLATFORM}` environment variable is set, the gateway will return an error. No silent fallback.
3. **Model proxy calls** (LLM requests) from OpenClaw are channel-agnostic and continue to work regardless of which channel initiated the conversation. The model proxy routes based on SPIFFE identity, not channel.

This is the expected behavior. The gateway enforces fail-closed: if a channel is not explicitly supported with a webhook receiver and egress endpoint, it cannot send or receive messages through the gateway.

---

## Extending Channel Support

There are two paths for adding new channel support, depending on whether source code changes are an option.

### Path 1: Without Source Code Changes (Pack + SDK)

Use this when you cannot or do not want to modify the PRECINCT gateway source. This is the recommended path for production deployments where the gateway is consumed as a dependency.

**How it works:**

The gateway's model proxy and tool plane are channel-agnostic. An external adapter service sits between the messaging platform and the gateway, handling:

1. **Inbound**: Receive platform webhooks, normalize to gateway API format, forward to the gateway's model proxy (`POST /openai/v1/chat/completions` or `/v1/messages`) or tool invocation endpoint.
2. **Outbound**: Receive model/tool responses from the gateway, format for the platform's send API, deliver.

**Implementation steps:**

1. **Build a channel adapter service** (any language):
   - Accept inbound webhooks from the messaging platform
   - Extract message content, sender identity, and platform metadata
   - Use the Go SDK (`sdk/go/`) or Python SDK (`sdk/python/`) to call the gateway
   - Format gateway responses for the platform's outbound API

2. **Register the service with SPIRE** for workload identity:
   - Obtain a SPIFFE ID (e.g., `spiffe://poc.local/channels/line`)
   - The gateway's OPA policy will evaluate this identity for authorization

3. **Author an app integration pack** (`pack.v1.json`):
   - Define route mappings, security expectations, and runtime hints
   - See [App Pack Authoring Guide](../sdk/app-pack-authoring-guide.md) for the full process

4. **Configure egress endpoints** via environment variables:
   ```
   MESSAGING_PLATFORM_ENDPOINT_LINE=https://api.line.me/v2/bot/message/push
   ```

5. **Validate** with the standard conformance gates:
   ```bash
   bash tests/e2e/validate_app_integration_pack_model.sh
   bash tests/e2e/validate_gateway_bypass_case26.sh
   ```

**SDK language support:**

| Language | SDK | Status |
|----------|-----|--------|
| Go | `sdk/go/` | Production-ready |
| Python | `sdk/python/` | Production-ready |
| Other | Use the gateway's HTTP/JSON-RPC API directly | See [API Reference](../api-reference.md) |

For languages without an SDK, the gateway's API is standard HTTP + JSON-RPC 2.0. Any HTTP client can integrate by following the wire format documented in the API reference.

**Automatic SPIFFE identity via Envoy sidecar:** If your adapter service (or any third-party tool) does not have native SPIFFE support, deploy it with the Envoy identity sidecar (`deploy/sidecar/`). The sidecar injects the `X-SPIFFE-ID` header into every outbound request, giving the tool a cryptographic identity without code changes. See [Sidecar Identity](../sidecar-identity.md) for Docker Compose and Kubernetes deployment instructions.

**Key constraint:** The external adapter service must route all LLM and tool traffic through the gateway. Direct calls to model providers or tool backends bypass security controls. Network-level controls (Docker network isolation or Kubernetes NetworkPolicy) enforce this boundary. The [No-Upstream-Mod Integration Playbook](../sdk/no-upstream-mod-integration-playbook.md) documents the boundary invariants.

### Path 2: With Source Code Changes (Port Adapter)

Use this when you have access to the PRECINCT source and want native gateway integration with per-channel webhook handling, DLP, and OPA policy.

**How it works:**

Add a webhook receiver to the OpenClaw port adapter (or create a new port adapter) that handles the platform's specific payload format.

**Implementation steps:**

1. **Add webhook receiver** in `ports/openclaw/webhook_receiver.go`:
   - Register a new webhook path constant (e.g., `lineWebhookPath = webhookBasePath + "/line"`)
   - Implement platform-specific payload extraction (parse the platform's webhook JSON into the unified `inboundMessage` struct)
   - Add to the `TryServeHTTP` routing

2. **Add egress endpoint resolution** in `internal/gateway/messaging_egress.go`:
   - Add the platform's send API URL to the default endpoint map
   - Implement platform-specific response parsing in `extractPlatformMessageID()`

3. **Register SPIFFE identity** for the new channel's webhooks:
   - The webhook receiver automatically uses `spiffe://poc.local/webhooks/{platform}`

4. **Add tests**:
   - Unit tests for payload extraction and egress formatting
   - Integration test for the full webhook-to-response cycle
   - Add to mock demo validation (`make demo-compose-mock`)

5. **Optional per-channel policy**: If the new channel needs different DLP sensitivity, rate limits, or authorization rules:
   - Add OPA policy rules in `ports/openclaw/policy/` (port-scoped, not core)
   - Core policies in `config/opa/` must remain unchanged

**Reference implementation:** The existing WhatsApp, Telegram, and Slack handlers in `ports/openclaw/webhook_receiver.go` are the canonical examples of this pattern.

---

## Per-Channel Features

The current implementation does not differentiate policy by channel. All messaging channels share:

- The same OPA authorization rules (`destination_allowed("messaging_send", ...)`)
- The same DLP scanning behavior (all inbound webhook content is scanned)
- The same rate limiting posture

If per-channel differentiation is needed (e.g., stricter DLP for public channels, different rate limits for high-volume platforms), this requires source code changes:

1. **Per-channel OPA policy**: Add channel-aware rules in `ports/openclaw/policy/` that key on the webhook SPIFFE identity (`spiffe://poc.local/webhooks/{platform}`).
2. **Per-channel rate limiting**: Extend the rate limiter to accept platform as a dimension in the rate key.
3. **Per-channel DLP sensitivity**: Add platform-aware DLP policy configuration in the port adapter.

These are extension points, not core changes. Port-scoped policy overlays keep the gateway core application-agnostic.

---

## Architecture Reference

The port adapter model is documented in:

- [App Integration Pack Model](../architecture/app-integration-pack-model.md) -- boundary rules and invariants
- [App Pack Authoring Guide](../sdk/app-pack-authoring-guide.md) -- step-by-step pack creation
- [No-Upstream-Mod Integration Playbook](../sdk/no-upstream-mod-integration-playbook.md) -- integration without source changes
- [OpenClaw Integration Pack](../../ports/openclaw/packs/README.md) -- reference implementation

The core principle: gateway core remains application-agnostic. All channel-specific adaptation lives in port adapters, integration packs, and SDK layers. Security outcomes are enforced in core and cannot be bypassed by adaptation layers.
