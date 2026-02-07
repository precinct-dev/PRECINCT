# ------------------------------------------------------------------------------
# Audit S3 IAM Role and Policy -- IRSA for Audit Log Sink
# Story: RFA-9fv.7
#
# Creates:
#   1. S3 bucket with Object Lock enabled (COMPLIANCE mode, 90-day retention)
#   2. IAM role trusted by EKS OIDC provider (for IRSA)
#   3. IAM policy with S3 PutObject + Object Lock permissions
#
# The gateway's ServiceAccount in observability namespace assumes this role
# to write hash-chained audit events to S3 with immutability guarantees.
#
# Prerequisites:
#   - EKS cluster with OIDC provider (from RFA-9fv.2 main.tf)
#   - Run `tofu init` and `tofu apply` from this directory
#
# Reference Architecture Section 10.9.2: S3 Object Lock requirements
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
  description = "EKS cluster name (must match RFA-9fv.2)"
  type        = string
  default     = "agentic-ref-arch-poc"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment label"
  type        = string
  default     = "poc"
}

variable "audit_bucket_name" {
  description = "S3 bucket name for audit logs"
  type        = string
  default     = "agentic-ref-arch-poc-audit-logs"
}

variable "retention_days" {
  description = "Object Lock retention period in days (minimum 90 per Ref Arch)"
  type        = number
  default     = 90
}

variable "oidc_provider_arn" {
  description = "ARN of the EKS OIDC provider (from RFA-9fv.2 outputs)"
  type        = string
}

variable "oidc_provider_url" {
  description = "URL of the EKS OIDC provider without https:// prefix"
  type        = string
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# S3 Bucket with Object Lock
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "audit_logs" {
  bucket = var.audit_bucket_name

  # Object Lock requires versioning; enabled via separate resource below.
  # Object Lock can only be enabled at bucket creation time.
  object_lock_enabled = true

  tags = {
    Project     = "agentic-ref-arch"
    Environment = var.environment
    ManagedBy   = "opentofu"
    Story       = "RFA-9fv.7"
    Purpose     = "audit-logs-immutable"
  }
}

# Enable versioning (required for Object Lock)
resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock configuration: COMPLIANCE mode with 90-day retention
resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit_logs]
}

# Block all public access to audit bucket
resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption with S3 managed keys
resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# ---------------------------------------------------------------------------
# IAM Role for IRSA (trusted by EKS OIDC provider)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "audit_s3_sink" {
  name = "${var.cluster_name}-audit-s3-sink"

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
            "${var.oidc_provider_url}:sub" = "system:serviceaccount:observability:audit-s3-sink"
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
    Story       = "RFA-9fv.7"
  }
}

# ---------------------------------------------------------------------------
# IAM Policy -- S3 PutObject + Object Lock permissions
# Scoped to the specific audit bucket and prefix.
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "audit_s3_write" {
  name = "${var.cluster_name}-audit-s3-write"
  role = aws_iam_role.audit_s3_sink.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAuditWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.audit_logs.arn}/audit/gateway/*"
      },
      {
        Sid    = "AllowObjectLockOperations"
        Effect = "Allow"
        Action = [
          "s3:PutObjectRetention",
          "s3:PutObjectLegalHold"
        ]
        Resource = "${aws_s3_bucket.audit_logs.arn}/audit/gateway/*"
      },
      {
        Sid    = "AllowBucketLocation"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.audit_logs.arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "audit_bucket_name" {
  description = "Name of the S3 bucket for audit logs"
  value       = aws_s3_bucket.audit_logs.id
}

output "audit_bucket_arn" {
  description = "ARN of the S3 bucket for audit logs"
  value       = aws_s3_bucket.audit_logs.arn
}

output "audit_iam_role_arn" {
  description = "ARN of the IAM role for the audit S3 sink (use in IRSA annotation)"
  value       = aws_iam_role.audit_s3_sink.arn
}

output "audit_iam_role_name" {
  description = "Name of the IAM role for the audit S3 sink"
  value       = aws_iam_role.audit_s3_sink.name
}
