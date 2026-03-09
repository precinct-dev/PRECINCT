---
id: OC-yrwz
title: "Data Source Integrity Registry"
status: closed
priority: 1
type: epic
created_at: 2026-03-08T02:32:10Z
created_by: ramirosalas
updated_at: 2026-03-09T01:45:23Z
content_hash: "sha256:66ff5c906b7bf5e2b816a1543565781181bade33905074231939559f1152c25c"
labels: [agents-of-chaos, data-source-integrity]
closed_at: 2026-03-09T01:45:23Z
close_reason: "All stories accepted"
---

## Description
## Business Context

Case Study #10 from 'Agents of Chaos' (Shapira et al., 2026, arXiv:2602.20021v1) documents an attacker planting a mutable external resource (a GitHub Gist 'constitution') that an agent fetches and trusts as authoritative. The agent's behavior is entirely controlled by the mutable document, enabling arbitrary manipulation of the agent's decision-making.

## Problem Being Solved

The tool registry (POC/internal/gateway/middleware/tool_registry.go) already performs SHA-256 hash verification for tool definitions (ToolDefinition with Hash field) and UI resources (RegisteredUIResource with ContentHash field), including rug-pull detection and poisoning pattern detection. However, it does NOT verify arbitrary external data sources that agents fetch and consume through the gateway. An attacker can mutate a data source (a document, configuration, or API response) after it has been approved, and the gateway will pass it through without verification.

## Target State

The tool registry concept is extended to cover external data resources. Any URL, file, or API endpoint an agent references can be registered with a content hash, approved by a known SPIFFE identity, and assigned a mutable policy (block_on_change, flag_on_change, allow). When the agent fetches a registered data source through the gateway, the response content is verified against the registered hash. Changes trigger blocking or flagging based on the configured policy. Unregistered external URIs are handled by a configurable UnknownDataSourcePolicy (default: flag).

## Architecture Integration

ToolRegistry (POC/internal/gateway/middleware/tool_registry.go) uses:
- Hot reload via fsnotify with atomic swap (sync.RWMutex)
- Ed25519 signature verification for registry YAML files (cosign-blob pattern)
- TOOL_REGISTRY_PUBLIC_KEY env var for verification key
- YAML schema for tool definitions with fields: Name, Description, Hash, InputSchema, AllowedDestinations, AllowedPaths, RiskLevel, RequiresStepUp, RequiredScope

RegisteredUIResource pattern (same file) with: ContentHash, Version, ApprovedAt, ApprovedBy, MaxSizeBytes, ScanResult -- the data source definition follows this pattern.

OPAInput struct (POC/internal/gateway/middleware/opa.go): SPIFFEID, Tool, Action, Method, Path, Params, StepUpToken, Session SessionInput, UI *UIInput.

SecurityFlagsCollector (POC/internal/gateway/middleware/context.go) with Append(flag string) for flag propagation.

AuditEvent struct (POC/internal/gateway/middleware/audit.go) with Timestamp, EventType, Severity, SessionID, DecisionID, TraceID, SPIFFEID, Action, Result, Method, Path, StatusCode, Security, Authorization.

## Acceptance Criteria

1. DataSourceDefinition struct added to tool_registry.go with URI, ContentHash, ApprovedAt, ApprovedBy, MaxSizeBytes, MutablePolicy, RefreshTTL, LastVerified fields
2. Registry YAML schema extended with data_sources: section
3. Content hash verification on data source fetch with block/flag on mismatch
4. Unregistered data sources handled by configurable policy (default: flag)
5. OPA policy for data source access control by SPIFFE ID
6. Hot reload and Ed25519 signature verification for data source registry (same pattern as tool registry)
7. E2E demo scenario demonstrating rug-pull detection with PROOF line

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T01:45:23Z status: open -> closed

## Links


## Comments
