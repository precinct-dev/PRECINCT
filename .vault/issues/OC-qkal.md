---
id: OC-qkal
title: "Principal Hierarchy Metadata Enrichment"
status: closed
priority: 2
type: epic
created_at: 2026-03-08T02:33:01Z
created_by: ramirosalas
updated_at: 2026-03-14T22:20:36Z
content_hash: "sha256:9028cc35fcce0d6e01702f8e0f65c4ae33730c77398064caf87ac02d375e660a"
labels: [agents-of-chaos, principal-hierarchy]
closed_at: 2026-03-08T17:35:05Z
close_reason: "Implemented and merged to main. nd not updated at delivery time -- closed retroactively."
---

## Description
## Business Context

The most fundamental finding in 'Agents of Chaos' (Shapira et al., 2026, arXiv:2602.20021v1): LLM agents cannot distinguish who they serve (owner vs. non-owner) because LLMs process instructions and data as indistinguishable tokens. Case Study #8 (identity spoofing) and Case Study #2 (non-owner compliance) demonstrate agents following instructions from unauthorized parties because they have no structured mechanism to evaluate the authority of a requester.

## Problem Being Solved

PRECINCT already has the infrastructure to solve this: SPIFFE IDs (step 3) map to cryptographic workload identities, and OPA policies (step 6) encode per-identity authorization. What is missing is propagating the resolved role/authority context INTO the agent's request/response flow as structured metadata. Currently, the gateway validates identity and enforces policy, but the agent (downstream of the proxy) receives no structured information about the requester's authority level. This means the agent framework cannot weight instructions based on the requester's role.

## Target State

The gateway resolves SPIFFE IDs to principal roles via OPA policy evaluation, then injects structured metadata headers into proxied requests. Downstream systems (including agent frameworks) can read headers like X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, and X-Precinct-Auth-Method to make authority-aware decisions. OPA policies are extended with principal-level-aware authorization rules.

## Architecture Integration

SPIFFE Auth (step 3, POC/internal/gateway/middleware/spiffe_auth.go):
- Extracts SPIFFE ID from X-SPIFFE-ID header (dev mode) or mTLS cert URI SAN (prod mode)
- Trust domain: poc.local (Compose) or agentic-ref-arch.poc (K8s)
- Config: SPIFFEMode string ("dev" or "prod"), SPIFFETrustDomain string (default: "poc.local")

OPA Policy evaluation (step 6, POC/internal/gateway/middleware/opa.go):
- OPAInput struct: SPIFFEID string, Tool string, Action string, Method string, Path string, Params map[string]interface{}, StepUpToken string, Session SessionInput, UI *UIInput
- OPA policies in POC/config/opa/: mcp_policy.rego, ui_policy.rego, exfiltration.rego, context_policy.rego, ui_csp_policy.rego

Config struct (POC/internal/gateway/config.go):
- OPAPolicyDir string -- directory containing .rego policy files
- SPIFFETrustDomain string -- default "poc.local"

AuditEvent struct: Timestamp, EventType, Severity, SessionID, DecisionID, TraceID, SPIFFEID, Action, Result, Method, Path

Header contract precedent: X-SPIFFE-ID, X-Session-ID (existing headers in api-reference.md)

## Acceptance Criteria

1. PrincipalRole struct defined with Level (0-5), Role, Capabilities, TrustDomain, AuthMethod
2. SPIFFE ID to principal role resolution via OPA policy evaluation
3. New rego policy file: POC/config/opa/principal_policy.rego
4. Request enrichment headers injected after SPIFFE auth and OPA evaluation: X-Precinct-Principal-Level, X-Precinct-Principal-Role, X-Precinct-Principal-Capabilities, X-Precinct-Auth-Method
5. Headers stripped from client requests and re-computed by gateway (cannot be forged)
6. OPA policies extended for principal-level-aware authorization
7. E2E demo scenario demonstrating principal hierarchy enforcement with PROOF lines

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T17:35:05Z status: open -> closed

## Links


## Comments
