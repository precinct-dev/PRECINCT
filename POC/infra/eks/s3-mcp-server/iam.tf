# ------------------------------------------------------------------------------
# S3 MCP Tool Server IAM Role (IRSA)
# Story: RFA-9fv.5
#
# IAM role for the S3 MCP tool server using IRSA (IAM Roles for Service Accounts).
# The role grants read-only S3 access scoped to specific buckets and prefixes.
#
# Trust policy:
#   - Only the s3-mcp-tool ServiceAccount in the tools namespace can assume this role
#   - Uses the EKS cluster's OIDC provider for identity verification
#
# Permissions (least-privilege):
#   - s3:ListBucket with prefix condition
#   - s3:GetObject with prefix condition
#   - No write, delete, or administrative operations
#
# Usage:
#   1. Set variables or override via terraform.tfvars
#   2. tofu init && tofu plan && tofu apply
#   3. Copy the output role ARN to s3-mcp-server-rbac.yaml annotation
#
# Prerequisites:
#   - EKS cluster with OIDC provider (from parent infra/eks/main.tf)
#   - tools namespace and s3-mcp-tool ServiceAccount deployed
# ------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "agentic-ref-arch-poc"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider (from parent tofu output: cluster_oidc_provider_arn)"
  type        = string
}

variable "oidc_provider_url" {
  description = "URL of the EKS OIDC provider without https:// (from parent tofu output: cluster_oidc_issuer_url)"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name to grant read access to"
  type        = string
  default     = "agentic-poc-data"
}

variable "s3_allowed_prefixes" {
  description = "List of S3 key prefixes to allow read access (e.g., ['documents/', 'reports/'])"
  type        = list(string)
  default     = ["documents/", "reports/"]
}

variable "namespace" {
  description = "Kubernetes namespace for the ServiceAccount"
  type        = string
  default     = "tools"
}

variable "service_account_name" {
  description = "Kubernetes ServiceAccount name"
  type        = string
  default     = "s3-mcp-tool"
}

variable "environment" {
  description = "Environment label"
  type        = string
  default     = "poc"
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# IAM Role with OIDC Trust Policy
# ---------------------------------------------------------------------------

resource "aws_iam_role" "s3_mcp_tool" {
  name = "${var.cluster_name}-s3-mcp-tool"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${var.oidc_provider_url}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
            "${var.oidc_provider_url}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Project     = "agentic-ref-arch"
    Environment = var.environment
    ManagedBy   = "opentofu"
    Story       = "RFA-9fv.5"
    Component   = "s3-mcp-tool"
  }
}

# ---------------------------------------------------------------------------
# IAM Policy -- Read-Only S3 Access (Scoped to Bucket + Prefixes)
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "s3_read_only" {
  name = "${var.cluster_name}-s3-mcp-tool-read-only"
  role = aws_iam_role.s3_mcp_tool.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowListBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.s3_bucket_name}"
        Condition = {
          StringLike = {
            "s3:prefix" = var.s3_allowed_prefixes
          }
        }
      },
      {
        Sid    = "AllowGetObject"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          for prefix in var.s3_allowed_prefixes :
          "arn:aws:s3:::${var.s3_bucket_name}/${prefix}*"
        ]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "s3_mcp_tool_role_arn" {
  description = "IAM role ARN for the S3 MCP tool ServiceAccount (use in s3-mcp-server-rbac.yaml annotation)"
  value       = aws_iam_role.s3_mcp_tool.arn
}

output "s3_mcp_tool_role_name" {
  description = "IAM role name"
  value       = aws_iam_role.s3_mcp_tool.name
}
