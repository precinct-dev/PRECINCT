---
id: OC-94gu
title: "Email Adapter -- Inbound Read Mediation with Data Classification"
status: closed
priority: 0
type: task
labels: [agents-of-chaos, channel-mediation, delivered, accepted]
parent: OC-0esa
created_at: 2026-03-08T02:36:57Z
created_by: ramirosalas
updated_at: 2026-03-08T03:33:43Z
content_hash: "sha256:dc814de3fb563c5a17a4a3b23655889910ad1c7c502d907debed26f88ebf6354"
was_blocked_by: [OC-tbd4]
follows: [OC-tbd4]
closed_at: 2026-03-08T03:33:43Z
close_reason: "Accepted: Email inbound read with content classification and exfiltration detection support"
---

## Description
## User Story

As a security operator, I need email read operations to be classified for data sensitivity so that the session context can detect exfiltration patterns -- if an agent reads sensitive email content and then calls an external tool, the gateway detects and blocks the data exfiltration attempt.

## Context

Reading email is a data access operation with security implications. The existing session context middleware (step 8, POC/internal/gateway/middleware/session_context.go) already tracks exfiltration patterns: it detects when an agent reads sensitive data (Classification="sensitive" in ToolAction) and then sends data to an external target (ExternalTarget=true) within 5 actions. The error code for this is "exfiltration_detected" (HTTP 403, step 8).

AgentSession.DataClassifications []string tracks the sensitivity level of data accessed in the session. ToolAction struct records: Timestamp, Tool, Resource, Classification string, ExternalTarget bool, DestinationDomain string.

KeyDB session store: session:{spiffe_id}:{session_id} -> JSON AgentSession, session:{spiffe_id}:{session_id}:actions -> LIST of ToolAction records. TTL: SESSION_TTL (default 3600s).

OPAInput struct: SPIFFEID, Tool, Action, Method, Path, Params, StepUpToken, Session SessionInput (RiskScore float64, PreviousActions []ToolAction).

## Implementation

Add handleList() and handleRead() to POC/ports/email/http_handler.go:

handleList():
1. Parse request as protocol.EmailListRequest (folder, max_items, page_token)
2. Build PlaneRequestV2 with tool name "email_read", action "list"
3. Call EvaluateToolRequest() -- OPA policy determines if this SPIFFE ID can list emails
4. If allowed: proxy to upstream email service
5. Record ToolAction with Classification="standard" (listing metadata is not sensitive)

handleRead():
1. Parse request as protocol.EmailReadRequest (email_id)
2. Build PlaneRequestV2 with tool name "email_read", action "read"
3. Call EvaluateToolRequest() -- OPA policy determines access
4. If allowed: proxy to upstream email service to retrieve email content
5. Auto-classify returned email content:
   - Scan content through DLP patterns (same patterns as step 7)
   - If content contains PII (SSN, credit card, etc.): Classification="sensitive"
   - If content contains credentials: Classification="sensitive"
   - Otherwise: Classification="standard"
6. Record ToolAction with computed Classification and ExternalTarget=false
7. Update AgentSession.DataClassifications if "sensitive" detected
8. This enables the existing exfiltration detection:
   - Agent reads email with sensitive content -> Classification="sensitive" recorded
   - Agent then calls external tool (e.g., discord send) -> ExternalTarget=true
   - Session context detects sensitive read followed by external send within 5 actions
   - Returns 403 with "exfiltration_detected"

OPA policy enforcement:
- Which SPIFFE IDs can read email
- Owner-only access vs. delegated access patterns
- Policy file: extend existing mcp_policy.rego or new rules in context_policy.rego

## Key Files

- POC/ports/email/http_handler.go (modify -- add handleList and handleRead)
- POC/ports/email/adapter.go (modify -- wire routes)

## Testing

- Unit tests: content classification (email with SSN classified as "sensitive", email without PII classified as "standard"), ToolAction recording with correct Classification, authorization enforcement
- Integration test: read sensitive email (containing SSN pattern) -> attempt external send (discord message) -> exfiltration detected and blocked with "exfiltration_detected" error code (HTTP 403, step 8)

## Acceptance Criteria

1. handleList() builds PlaneRequestV2 with tool name "email_read" and action "list"
2. handleRead() builds PlaneRequestV2 with tool name "email_read" and action "read"
3. Email content auto-classified using DLP patterns: PII or credentials -> Classification="sensitive"
4. ToolAction recorded with computed Classification for session tracking
5. AgentSession.DataClassifications updated when sensitive content detected
6. Exfiltration detection works: sensitive email read followed by external tool call triggers "exfiltration_detected" (HTTP 403)
7. OPA policy enforces SPIFFE ID authorization for email read operations
8. Unit tests verify content classification and ToolAction recording
9. Integration test demonstrates full exfiltration detection chain

## Dependencies

Depends on OC-tbd4 (email adapter core router).

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes
COMPLETED: Implementation of handleList and handleRead with DLP content classification. All 24 unit tests pass. Integration tests updated. Pushed to story/OC-94gu.

## History
- 2026-03-08T03:33:43Z dep_removed: no_longer_blocks OC-di1n

## Links
- Parent: [[OC-0esa]]
- Was blocked by: [[OC-tbd4]]
- Follows: [[OC-tbd4]]

## Comments
