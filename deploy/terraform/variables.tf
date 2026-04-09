# ------------------------------------------------------------------------------
# Input Variables -- EKS Cluster Baseline
# All defaults are tuned for the POC environment.
# Override via terraform.tfvars or -var flags.
# ------------------------------------------------------------------------------

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "precinct-poc"
}

variable "region" {
  description = "AWS region for the cluster"
  type        = string
  default     = "us-west-2"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster"
  type        = string
  default     = "1.29"
}

variable "node_instance_type" {
  description = "EC2 instance type for the managed node group"
  type        = string
  default     = "t3.medium"
}

variable "node_min_size" {
  description = "Minimum number of nodes in the managed node group"
  type        = number
  default     = 2
}

variable "node_max_size" {
  description = "Maximum number of nodes in the managed node group"
  type        = number
  default     = 4
}

variable "node_desired_size" {
  description = "Desired number of nodes in the managed node group"
  type        = number
  default     = 2
}

variable "environment" {
  description = "Environment label (e.g., poc, staging, production)"
  type        = string
  default     = "poc"
}
