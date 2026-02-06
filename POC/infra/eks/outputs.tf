# ------------------------------------------------------------------------------
# Outputs -- Values needed by downstream stories and operators
# cluster_oidc_issuer_url is critical for RFA-9fv.3 (SPIRE/IRSA integration).
# ------------------------------------------------------------------------------

output "cluster_endpoint" {
  description = "EKS cluster API server endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded certificate data for the cluster CA"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL for the EKS cluster (needed for SPIRE/IRSA in RFA-9fv.3)"
  value       = module.eks.cluster_oidc_issuer_url
}

output "cluster_oidc_provider_arn" {
  description = "ARN of the OIDC provider (needed for IAM roles for service accounts)"
  value       = module.eks.oidc_provider_arn
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_id" {
  description = "Security group ID attached to the EKS managed node group"
  value       = module.eks.node_security_group_id
}

output "vpc_id" {
  description = "ID of the VPC created for the EKS cluster"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (where EKS nodes run)"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (for load balancers)"
  value       = module.vpc.public_subnets
}
