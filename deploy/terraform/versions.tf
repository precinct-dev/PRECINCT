# ------------------------------------------------------------------------------
# Version Constraints -- OpenTofu/Terraform and Provider Versions
# OpenTofu >= 1.6 is required (forked from Terraform 1.6.x).
# Compatible with Terraform >= 1.6 if you prefer to use that instead.
# ------------------------------------------------------------------------------

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
}

# AWS Provider configuration
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "precinct"
      Environment = var.environment
      ManagedBy   = "opentofu"
    }
  }
}
