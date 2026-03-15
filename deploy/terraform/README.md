# EKS Cluster Baseline -- PRECINCT POC

**NOTE: This is an AWS/EKS-specific optional overlay.** For cloud-agnostic
Kubernetes manifests that work on any conformant cluster (EKS, GKE, AKS, kind,
k3s, etc.), see `deploy/k8s/`. The EKS-specific resources here (Terraform,
IRSA, VPC CNI, S3 audit sink) layer on top of the generic k8s base.

IaC scripts for provisioning an EKS cluster in AWS us-west-2 using OpenTofu and the `terraform-aws-modules/eks` community module.

Story: RFA-9fv.2 | Spike: RFA-9fv.1 (see `docs/eks-iac.md`)

## Prerequisites

1. **OpenTofu** >= 1.6 (or Terraform >= 1.6)
   ```bash
   # macOS
   brew install opentofu

   # Linux (snap)
   snap install opentofu --classic

   # Verify
   tofu --version
   ```

2. **AWS CLI** configured with credentials that have the permissions listed in `docs/eks-iac.md` (Required AWS Permissions section).
   ```bash
   aws configure
   aws sts get-caller-identity  # Verify access
   ```

3. **kubectl** for interacting with the cluster after creation.
   ```bash
   brew install kubectl  # or: https://kubernetes.io/docs/tasks/tools/
   ```

## Quick Start

```bash
cd deploy/terraform

# 1. Initialize providers and modules
make init

# 2. (Optional) Copy and edit variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars as needed

# 3. Preview what will be created
make plan

# 4. Create the cluster (~15-20 minutes)
make apply

# 5. Configure kubectl
aws eks update-kubeconfig --name precinct-poc --region us-west-2

# 6. Verify
kubectl get nodes
```

## Destroy

To tear down the cluster and all associated resources (VPC, subnets, NAT gateway, etc.):

```bash
make destroy
```

This will prompt for confirmation before deleting anything.

## Remote State (Optional)

By default, state is stored locally. For team use, enable remote state in S3:

1. Create the S3 bucket and DynamoDB lock table (see instructions in `backend.tf`)
2. Uncomment the backend block in `backend.tf`
3. Run `tofu init` to migrate state

## What Gets Created

| Resource | Details |
|----------|---------|
| VPC | Dedicated VPC (10.0.0.0/16) across 3 AZs |
| Subnets | 3 private (nodes) + 3 public (load balancers) |
| NAT Gateway | Single (POC cost optimization) |
| EKS Cluster | Kubernetes 1.29, OIDC enabled |
| Node Group | 2-4 t3.medium instances (managed, on-demand) |
| Add-ons | CoreDNS, kube-proxy, VPC CNI (with NetworkPolicy) |

## Estimated Monthly Cost

Based on the spike analysis (docs/eks-iac.md):

| Component | Cost/Month |
|-----------|-----------|
| EKS Control Plane | $73 |
| 2x t3.medium (default) | ~$61 |
| NAT Gateway | ~$33 |
| EBS (root volumes) | ~$3 |
| **Total** | **~$170/month** |

Scale up to 4 nodes adds ~$61/month. See the spike document for cost optimization strategies.

## Files

| File | Purpose |
|------|---------|
| `main.tf` | VPC and EKS cluster configuration |
| `variables.tf` | Input variables with defaults |
| `outputs.tf` | Cluster endpoint, OIDC URL, VPC IDs |
| `versions.tf` | OpenTofu/provider version constraints |
| `backend.tf` | Remote state config (commented out) |
| `terraform.tfvars.example` | Example variable overrides |

## Next Steps

- **RFA-9fv.3**: Deploy SPIRE/SPIKE on this cluster (uses `cluster_oidc_issuer_url` output)
- **RFA-9fv.4**: Deploy gateway and agents as Kubernetes workloads
