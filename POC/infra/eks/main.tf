# ------------------------------------------------------------------------------
# Agentic Reference Architecture POC -- EKS Cluster Baseline
# Story: RFA-9fv.2
#
# Creates a VPC and EKS cluster in us-west-2 with:
#   - Dedicated VPC across 3 AZs (private subnets for nodes, public for LBs)
#   - EKS 1.29 with managed node groups (2-4 t3.medium)
#   - OIDC provider enabled (required for SPIRE/IRSA in RFA-9fv.3)
#   - VPC CNI with NetworkPolicy support
#   - CoreDNS, kube-proxy add-ons
# ------------------------------------------------------------------------------

# Data sources
data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  cluster_name = var.cluster_name
  region       = var.region

  # Use first 3 AZs in the region
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  # VPC CIDR and subnet allocation
  vpc_cidr        = "10.0.0.0/16"
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  common_tags = {
    Project     = "agentic-ref-arch"
    Environment = var.environment
    ManagedBy   = "opentofu"
    Story       = "RFA-9fv.2"
  }
}

# ------------------------------------------------------------------------------
# VPC -- Dedicated network for the EKS cluster
# Uses terraform-aws-modules/vpc for production-quality networking.
# Single NAT gateway for cost optimization in POC (~$33/month vs ~$99 for per-AZ).
# ------------------------------------------------------------------------------
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.cluster_name}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = local.private_subnets
  public_subnets  = local.public_subnets

  # Single NAT gateway for POC cost optimization.
  # For production, set enable_nat_gateway = true and one_nat_gateway_per_az = true.
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Tags required for EKS auto-discovery of subnets
  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = 1
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  tags = local.common_tags
}

# ------------------------------------------------------------------------------
# EKS Cluster -- Managed Kubernetes with OIDC and NetworkPolicy
# Uses terraform-aws-modules/eks v21+ for managed node groups, OIDC, and add-ons.
# OIDC provider is critical for SPIRE/IRSA integration (RFA-9fv.3).
# ------------------------------------------------------------------------------
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name               = local.cluster_name
  kubernetes_version = var.kubernetes_version

  # Cluster endpoint access: private + public for POC convenience.
  # For production, consider disabling public access entirely.
  endpoint_public_access  = true
  endpoint_private_access = true

  # OIDC provider -- required for SPIRE workload identity and IRSA
  enable_irsa = true

  # VPC configuration
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Allow the cluster creator (current IAM principal) admin access
  enable_cluster_creator_admin_permissions = true

  # EKS Add-ons
  addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        # Enable NetworkPolicy support via VPC CNI
        enableNetworkPolicy = "true"
      })
    }
  }

  # Managed node group -- the worker nodes that run our workloads
  eks_managed_node_groups = {
    default = {
      name = "${local.cluster_name}-nodes"

      instance_types = [var.node_instance_type]
      capacity_type  = "ON_DEMAND"

      min_size     = var.node_min_size
      max_size     = var.node_max_size
      desired_size = var.node_desired_size

      # Use latest Amazon Linux 2023 EKS-optimized AMI
      ami_type = "AL2023_x86_64_STANDARD"

      # Node disk size
      disk_size = 20

      labels = {
        role        = "general"
        environment = var.environment
      }

      tags = local.common_tags
    }
  }

  tags = local.common_tags
}
