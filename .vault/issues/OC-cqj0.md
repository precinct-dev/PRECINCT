---
id: OC-cqj0
title: "DataSourceDefinition Struct and Registry Extension"
status: closed
priority: 1
type: task
labels: [agents-of-chaos, data-source-integrity, delivered, accepted]
parent: OC-yrwz
created_at: 2026-03-08T02:38:06Z
created_by: ramirosalas
updated_at: 2026-03-09T00:27:11Z
content_hash: "sha256:662aef31c204913d0782ce7142a3227f3a8bf5863a6ea53db52dfd7511d36221"
closed_at: 2026-03-09T00:27:11Z
close_reason: "Accepted: DataSourceDefinition struct, registry extension, GetDataSource(), ComputeDataSourceHash(), hot-reload, and Ed25519 attestation all implemented and verified. 17 tests pass, race detector clean, no skips."
led_to: [OC-am3w, OC-9aac, OC-4zrf]
---

## Description
## User Story

As a security operator, I need to register external data sources with content hashes so that the gateway can detect when an attacker mutates a trusted data source (rug-pull attack, Case Study #10 of 'Agents of Chaos', arXiv:2602.20021v1).

## Context

The tool registry (POC/internal/gateway/middleware/tool_registry.go) already manages ToolDefinition and RegisteredUIResource with content hash verification, hot reload via fsnotify, and Ed25519 signature verification. This story extends the same registry to cover arbitrary external data sources.

Existing ToolDefinition fields: Name, Description, Hash string (yaml:"hash"), InputSchema, AllowedDestinations, AllowedPaths, RiskLevel string (yaml:"risk_level"), RequiresStepUp bool, RequiredScope string.

Existing RegisteredUIResource fields: Server, ResourceURI, ContentHash string (yaml:"content_hash"), Version, ApprovedAt time.Time, ApprovedBy string, MaxSizeBytes int64, DeclaredCSP, DeclaredPerms, ScanResult.

Hot reload pattern: fsnotify watcher on registry YAML file, verifySignature(data, sig) with TOOL_REGISTRY_PUBLIC_KEY env var, atomic swap via sync.RWMutex.

Registry YAML file: config/tool-registry.yaml (path from Config.ToolRegistryConfigPath).

## Implementation

Add to POC/internal/gateway/middleware/tool_registry.go:

```go
type DataSourceDefinition struct {
    URI           string        `yaml:"uri" json:"uri"`              // e.g., "https://gist.github.com/..."
    ContentHash   string        `yaml:"content_hash" json:"content_hash"` // SHA-256 of approved content
    ApprovedAt    time.Time     `yaml:"approved_at" json:"approved_at"`
    ApprovedBy    string        `yaml:"approved_by" json:"approved_by"`   // SPIFFE ID of approver
    MaxSizeBytes  int64         `yaml:"max_size_bytes" json:"max_size_bytes"`
    MutablePolicy string        `yaml:"mutable_policy" json:"mutable_policy"` // "block_on_change", "flag_on_change", "allow"
    RefreshTTL    time.Duration `yaml:"refresh_ttl" json:"refresh_ttl"`       // how often to re-verify
    LastVerified  time.Time     `yaml:"last_verified" json:"last_verified"`
}
```

Extend the registry YAML schema to include a data_sources: section:
```yaml
tools:
  - name: tavily_search
    ...
ui_resources:
  - server: openclaw
    ...
data_sources:
  - uri: "https://gist.github.com/owner/abc123/raw"
    content_hash: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    approved_at: "2026-03-01T00:00:00Z"
    approved_by: "spiffe://poc.local/admin/security"
    max_size_bytes: 1048576
    mutable_policy: "block_on_change"
    refresh_ttl: "1h"
```

Add to ToolRegistry struct:
- DataSources []DataSourceDefinition field
- GetDataSource(uri string) (*DataSourceDefinition, bool) method
- parseDataSources() in YAML loading
- Include data sources in hot reload and signature verification (same fsnotify + cosign-blob pattern)

Hash computation: SHA-256 using crypto/sha256, hex-encoded with "sha256:" prefix (same pattern as ContentHash in RegisteredUIResource).

## Key Files

- POC/internal/gateway/middleware/tool_registry.go (modify)
- POC/config/tool-registry.yaml (modify -- add data_sources section)

## Testing

- Unit tests: YAML parsing with data_sources section, DataSourceDefinition field validation, hash computation and comparison, GetDataSource lookup (found and not-found), hot reload includes data sources
- Integration test: load registry with data sources, verify hot reload updates data sources atomically

## Acceptance Criteria

1. DataSourceDefinition struct added to tool_registry.go with URI, ContentHash, ApprovedAt, ApprovedBy, MaxSizeBytes, MutablePolicy, RefreshTTL, LastVerified fields
2. Registry YAML schema extended with data_sources: section
3. ToolRegistry struct gains DataSources field and GetDataSource(uri) method
4. Data sources included in hot reload via existing fsnotify watcher
5. Ed25519 signature verification applies to registry file including data_sources (same cosign-blob pattern, TOOL_REGISTRY_PUBLIC_KEY)
6. SHA-256 hash format: "sha256:" prefix + hex-encoded digest
7. Unit tests cover YAML parsing, hash computation, lookup, and hot reload

## Scope Boundary

This story creates the data structure and registry extension ONLY. Verification middleware logic is story 2.2. OPA policy is story 2.3.

MANDATORY SKILLS TO REVIEW:
None identified

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-09T00:27:11Z dep_removed: no_longer_blocks OC-9aac

## Links
- Parent: [[OC-yrwz]]
- Led to: [[OC-am3w]], [[OC-9aac]], [[OC-4zrf]]

## Comments
