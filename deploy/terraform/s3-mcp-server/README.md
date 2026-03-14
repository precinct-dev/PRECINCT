# S3 MCP Tool Server - EKS Deployment

Story: RFA-9fv.5

## Overview

The S3 MCP tool server is a Go microservice that implements the MCP JSON-RPC protocol
for S3 access. It provides two tools:

- **s3_list_objects**: List objects in an S3 bucket with an allowed prefix
- **s3_get_object**: Read object content from an S3 bucket with an allowed prefix

## Security

- **Destination Allowlist**: Configured via `ALLOWED_BUCKETS` environment variable
  (format: `bucket:prefix,bucket:prefix`). Requests for non-allowed buckets/prefixes
  are rejected at the application layer BEFORE any S3 API call.
- **IRSA**: Uses IAM Roles for Service Accounts for AWS credentials (no static keys).
  IAM policy scopes permissions to specific S3 bucket and prefixes.
- **NetworkPolicy**: Ingress restricted to gateway namespace only. Egress allows
  DNS and HTTPS (443) for AWS S3 endpoints.
- **SPIFFE**: Mounts SPIRE agent socket for workload identity.

## Files

| File | Purpose |
|------|---------|
| `s3-mcp-server-rbac.yaml` | ServiceAccount with IRSA annotation |
| `s3-mcp-server-configmap.yaml` | Allowlist and AWS region configuration |
| `s3-mcp-server-deployment.yaml` | Deployment (port 8082, distroless image) |
| `s3-mcp-server-service.yaml` | ClusterIP service on port 8082 |
| `s3-mcp-server-networkpolicy.yaml` | Ingress/egress network policies |
| `iam.tf` | IAM role and policy (OpenTofu) |
| `Makefile` | Deploy/verify/dry-run/undeploy targets |

## Prerequisites

1. EKS cluster deployed (`make -C .. apply` in `infra/eks/`)
2. `tools` namespace exists (from `make -C ../mcp-server deploy`)
3. SPIRE deployed (`make -C ../spire deploy`)
4. IAM role created: `cd s3-mcp-server && tofu init && tofu apply`
5. Docker image built: `docker build -f docker/Dockerfile.s3-mcp-server -t s3-mcp-server .`

## Deployment

```bash
# 1. Create IAM role
tofu init && tofu apply

# 2. Update IRSA annotation in s3-mcp-server-rbac.yaml with the role ARN output

# 3. Deploy
make deploy

# 4. Verify
make verify
```

## Configuration

Edit `s3-mcp-server-configmap.yaml` to customize:

- `ALLOWED_BUCKETS`: Comma-separated list of `bucket:prefix` pairs
- `AWS_REGION`: AWS region for S3 API calls

## Validation

```bash
make dry-run  # Offline manifest validation with kubeconform
```
