---
id: OC-0esa
title: "Communication Channel Mediation Adapters"
status: closed
priority: 0
type: epic
created_at: 2026-03-08T02:31:46Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:787cf62a5d2dad688f4001d2fdd4868c4d4dd33f5ec286ffaa017584a1d332fe"
labels: [agents-of-chaos, channel-mediation]
closed_at: 2026-03-08T17:35:04Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## Business Context

The paper 'Agents of Chaos' (Shapira et al., 2026, arXiv:2602.20021v1) documents 16 case studies from a red-teaming exercise against autonomous LLM agents. Case Studies #4 (resource looping via Discord), #10 (mutable external resource trust), and #11 (mass email broadcasts) demonstrate that agent-to-agent communication via Discord and email bypasses ALL security controls when traffic does not traverse the gateway. This is the single most impactful gap because it renders all 13 middleware layers irrelevant for a major class of agent interactions.

## Problem Being Solved

Currently, agents can send Discord messages and emails through direct API calls that bypass the PRECINCT gateway entirely. When this happens: DLP scanning (step 7) cannot catch credential leakage in messages, session context (step 8) cannot track behavioral patterns across communication channels, rate limiting (step 11) cannot prevent infinite message loops, and OPA policy (step 6) cannot enforce authorization on who agents can communicate with.

## Target State

Port adapters (following the OpenClaw adapter pattern in POC/ports/openclaw/) mediate Discord and email traffic through the full 13-layer middleware chain. Agents send Discord messages and emails by calling the gateway's adapter endpoints, which evaluate the request through all middleware layers before delivering the message via the external API. Inbound webhooks from Discord and email services also traverse the middleware chain for injection detection and audit logging.

## Architecture Integration

Port adapter pattern: PortAdapter interface (POC/internal/gateway/port.go) with Name() string and TryServeHTTP(w http.ResponseWriter, r *http.Request) bool. Adapters run INSIDE the middleware chain. Registration at startup in cmd/gateway/main.go. Gateway services exposed via PortGatewayServices facade with:
- EvaluateToolRequest(req PlaneRequestV2) ToolPlaneEvalResult -- for policy evaluation
- ExecuteMessagingEgress(ctx context.Context, attrs map[string]string, payload []byte, authHeader string) (*MessagingEgressResult, error) -- for outbound delivery
- RedeemSPIKESecret(ctx context.Context, tokenStr string) (string, error) -- for late-binding credentials
- ValidateConnector(connectorID, signature string) (bool, string) -- for inbound webhook validation
- AuditLog(event middleware.AuditEvent) -- for audit event emission
- WriteGatewayError(w, r, httpCode, errorCode, message, middlewareName, reason, details) -- for error responses

PlaneRequestV2 struct (POC/internal/gateway/phase3_contracts.go) with Envelope RunEnvelope and Policy PolicyInputV2.

DLP scanning: DLPPolicy with Credentials="block", Injection="flag", PII="flag" defaults. Detects credentials (OpenAI, AWS, GitHub, Slack tokens, PEM blocks, passwords), PII (SSN, email, phone, credit card, IBAN, DOB), injection (SQL, prompt injection patterns).

Rate limiting: per-identity token bucket via KeyDB. Keys: ratelimit:{spiffe_id}:tokens, ratelimit:{spiffe_id}:last_fill.

Session context: AgentSession with ID, SPIFFEID, StartTime, Actions []ToolAction, DataClassifications []string, RiskScore float64, Flags []string. ToolAction with Timestamp, Tool, Resource, Classification, ExternalTarget bool, DestinationDomain string.

SPIKE token references: $SPIKE{ref:...} pattern, redeemed by TokenSubstitution middleware (step 13).

SecurityFlagsCollector (POC/internal/gateway/middleware/context.go) with Flags []string and Append(flag string) method.

## Acceptance Criteria

1. Discord port adapter registered in gateway and claiming /discord/* paths
2. Email port adapter registered in gateway and claiming /email/* paths
3. Outbound Discord messages traverse full middleware chain (DLP, rate limiting, session context, OPA)
4. Outbound emails traverse full middleware chain with recipient policy enforcement
5. Inbound Discord webhooks validated and scanned for injection
6. Inbound email events classified for data sensitivity
7. E2E demo scenarios demonstrate all blocking behaviors with PROOF lines
8. All adapters follow the OpenClaw adapter pattern exactly

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:04Z status: open -> closed

## Links


## Comments
