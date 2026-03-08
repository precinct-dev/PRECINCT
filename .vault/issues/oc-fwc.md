---
id: oc-fwc
title: "Fix malformed ARN placeholders in infra/eks RBAC manifests"
status: closed
priority: 1
type: bug
assignee: ramxx@ramirosalas.com
created_at: 2026-02-21T17:54:03Z
created_by: ramirosalas
updated_at: 2026-03-08T02:10:22Z
content_hash: "sha256:54a1a6fe0f0efa27633a040481b3e78d4084534278ab569961339715376e9f97"
closed_at: 2026-02-21T17:56:58Z
close_reason: "Fixed both malformed ARN placeholders: removed extra colon in audit-s3-rbac.yaml (iam::: -> iam::) and added missing <ACCOUNT_ID> placeholder in s3-mcp-server-rbac.yaml (iam::role -> iam::<ACCOUNT_ID>:role). YAML validation passes. grep sweep confirms no other malformed ARNs in infra/."
parent: oc-l5u
led_to: [oc-a8e]
---

## Description
## User Story

As a platform engineer deploying the MCP Security Gateway to EKS, I need the IRSA ServiceAccount manifests to have syntactically valid ARN placeholders so that replacing the placeholder with a real account ID produces a valid IAM role ARN that passes AWS IAM validation.

## Context

Two Kubernetes ServiceAccount manifests in infra/eks/ have malformed ARN strings in their IRSA annotations. These are placeholder values intended to be replaced before deployment, but the placeholder format itself is broken -- even after substitution, the resulting ARNs would be malformed and fail IAM validation.

## Defect Details

### Defect 1: Triple colon in audit-s3-rbac.yaml

File: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/infra/eks/observability/audit/audit-s3-rbac.yaml
Line: 33

Current (BROKEN):
```yaml
eks.amazonaws.com/role-arn: "arn:aws:iam:::<ACCOUNT_ID>:role/agentic-ref-arch-poc-audit-s3-sink"
```

The ARN has THREE colons between "iam" and "<ACCOUNT_ID>" (iam:::<ACCOUNT_ID>). A valid IAM ARN has exactly TWO colons: arn:aws:iam::<ACCOUNT_ID>:role/...

The extra colon means even after replacing <ACCOUNT_ID> with e.g. 123456789012, the result would be:
  arn:aws:iam:::123456789012:role/... (INVALID -- three colons, no region is fine but the extra colon creates a malformed partition)

Fix: Remove the extra colon to produce:
```yaml
eks.amazonaws.com/role-arn: "arn:aws:iam::<ACCOUNT_ID>:role/agentic-ref-arch-poc-audit-s3-sink"
```

### Defect 2: Missing account ID placeholder in s3-mcp-server-rbac.yaml

File: /Users/ramirosalas/workspace/agentic_reference_architecture/POC/infra/eks/s3-mcp-server/s3-mcp-server-rbac.yaml
Line: 29

Current (BROKEN):
```yaml
eks.amazonaws.com/role-arn: "arn:aws:iam::role/s3-mcp-tool-role"
```

The ARN has NO account ID at all between the colons (iam::role/...). A valid IAM ARN requires the account ID: arn:aws:iam::<ACCOUNT_ID>:role/...

The current value would fail IAM validation immediately -- there is no placeholder for the operator to replace.

Fix: Add the <ACCOUNT_ID> placeholder to match the pattern used elsewhere:
```yaml
eks.amazonaws.com/role-arn: "arn:aws:iam::<ACCOUNT_ID>:role/s3-mcp-tool-role"
```

## AWS ARN Format Reference

Valid IAM role ARN format: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
                           ^   ^   ^   ^^           ^

                           |   |   |   ||           |
                           arn partition service  region(empty for IAM)  account  resource

For IAM, the region field is always empty, resulting in two consecutive colons (::) between the service and account ID. Three colons or missing account ID are always invalid.

## Acceptance Criteria

1. audit-s3-rbac.yaml line 33 contains exactly: arn:aws:iam::<ACCOUNT_ID>:role/agentic-ref-arch-poc-audit-s3-sink
2. s3-mcp-server-rbac.yaml line 29 contains exactly: arn:aws:iam::<ACCOUNT_ID>:role/s3-mcp-tool-role
3. Both ARNs match the standard AWS IAM ARN format: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
4. No other files are modified
5. The comment on line 31-32 of audit-s3-rbac.yaml still says "Replace <ACCOUNT_ID>" (already correct)
6. The comment on line 28 of s3-mcp-server-rbac.yaml is updated to say "Replace <ACCOUNT_ID>" if it does not already mention this

## Testing Requirements

- Unit tests: Not applicable (YAML manifests, no executable code)
- Integration tests: Not technically feasible for infrastructure YAML placeholders. These manifests are deployment artifacts, not runtime code. Validation is visual/structural.
- Verification: grep for "arn:aws:iam:" across all files in infra/eks/ to confirm no other malformed ARNs exist. Expected pattern: exactly two colons between "iam" and the account ID field.

## Files to Modify

- /Users/ramirosalas/workspace/agentic_reference_architecture/POC/infra/eks/observability/audit/audit-s3-rbac.yaml (line 33)
- /Users/ramirosalas/workspace/agentic_reference_architecture/POC/infra/eks/s3-mcp-server/s3-mcp-server-rbac.yaml (line 29)

## Scope Boundary

This story fixes ONLY the two identified malformed ARNs. It does not create Terraform modules, deploy anything, or validate other infra YAML files beyond a grep sweep for similar issues.

## Dependencies

None. This story is independent.

MANDATORY SKILLS TO REVIEW:
- None identified. Standard YAML editing with AWS ARN format knowledge, no specialized skill requirements.

## Acceptance Criteria


## Design


## Notes


## History
- 2026-03-08T02:10:22Z status: open -> closed

## Links
- Parent: [[oc-l5u]]
- Led to: [[oc-a8e]]

## Comments
