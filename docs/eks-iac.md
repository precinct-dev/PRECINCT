# EKS IaC Approach -- Spike Recommendation

**Spike:** RFA-9fv.1
**Date:** 2026-02-05
**Context:** PRECINCT -- choose an IaC tool for provisioning an EKS cluster in a single AWS account, us-west-2 (Oregon).

---

## Recommendation: OpenTofu (Terraform-Compatible)

**Use OpenTofu with the `terraform-aws-modules/eks` community module** for provisioning the EKS cluster.

OpenTofu is a drop-in replacement for Terraform that uses the same HCL configuration language, the same provider ecosystem (including the AWS provider), and the same module registry. It avoids the licensing concerns introduced by HashiCorp's BSL license change while retaining the full ecosystem maturity that makes Terraform the de facto IaC standard.

### Why OpenTofu over Terraform directly?

1. **License:** OpenTofu is MPL-2.0 (genuinely open source). Terraform moved to BSL in 2023, which restricts competitive use. For a reference architecture that others will fork and deploy, an open-source license is preferable.
2. **Compatibility:** OpenTofu maintains protocol compatibility with all Terraform providers and modules. The `terraform-aws-modules/eks` module (v21.15.1, 721K+ weekly downloads) works unchanged.
3. **Foundation parity:** OpenTofu forked from Terraform 1.6.x and tracks the same HCL syntax and state format. Migration is trivial (rename binary, no config changes).
4. **Community momentum:** Backed by the Linux Foundation with long-term provider compatibility pledges.

If the team later decides Terraform's BSL is acceptable, switching back requires zero configuration changes -- only a binary swap.

---

## Options Evaluated

### 1. OpenTofu / Terraform (HCL)

| Aspect | Assessment |
|--------|-----------|
| **Maturity** | Terraform: 10+ years, the most widely adopted IaC tool. OpenTofu: 2+ years, backed by Linux Foundation. |
| **EKS Support** | Best-in-class via `terraform-aws-modules/eks` (v21.15.1). Supports EKS Auto Mode, managed node groups, Fargate, Karpenter, OIDC. |
| **State Management** | Explicit state file (S3 + DynamoDB locking for teams). Clear drift detection. |
| **Multi-Cloud** | 3,900+ providers. Can manage non-AWS resources (Kubernetes manifests, Helm, DNS) in the same codebase. |
| **Community** | Largest IaC community. Extensive documentation, tutorials, Stack Overflow answers. |
| **Learning Curve** | HCL is purpose-built and readable. Most DevOps engineers already know it. |
| **CI/CD Integration** | Native support in GitHub Actions, GitLab CI, all major CI systems. `plan` + `apply` workflow is well understood. |
| **Modularity** | Terraform modules enable reusable, composable infrastructure. The EKS module is battle-tested. |

**Pros:**
- Declarative, reproducible, and auditable
- Massive ecosystem of modules and providers
- `terraform plan` provides a clear preview before changes
- State locking prevents concurrent modification
- Supports importing existing resources
- Well-understood `plan` -> `apply` -> `destroy` lifecycle
- The `terraform-aws-modules/eks` module handles VPC, subnets, OIDC, node groups, add-ons, and IAM roles in a single cohesive module

**Cons:**
- Requires state management (S3 bucket + DynamoDB table for remote state)
- HCL is another language to learn (though simple and well-documented)
- Terraform's BSL license may concern some organizations (mitigated by using OpenTofu)
- Day-2 operations (e.g., Kubernetes resource management) require the Kubernetes/Helm providers or separate tooling

### 2. eksctl

| Aspect | Assessment |
|--------|-----------|
| **Maturity** | 6+ years, official EKS CLI maintained by Weaveworks (now AWS-affiliated). |
| **EKS Support** | Purpose-built for EKS. Fastest path to a running cluster. |
| **State Management** | Uses CloudFormation stacks as implicit state. No separate state file needed. |
| **Multi-Cloud** | None. EKS-only. |
| **Community** | Active but narrower than Terraform. Documentation is good but EKS-specific. |
| **Learning Curve** | Lowest. YAML config or CLI flags. Can create a cluster in one command. |
| **CI/CD Integration** | Can be scripted but lacks native `plan`/`diff` workflow. Changes are applied directly. |

**Pros:**
- Fastest time-to-cluster (single command: `eksctl create cluster`)
- YAML configuration is simple and Kubernetes-native
- Built-in support for managed node groups, Fargate, GitOps (Flux)
- Generates CloudFormation, so resources are tracked in AWS natively
- Good default security settings (private endpoint, encryption)

**Cons:**
- **No preview/plan mode** -- changes are applied directly, no dry-run for infrastructure changes
- CloudFormation stacks can be fragile and hard to debug when they fail
- Limited to EKS resources only -- cannot manage VPC, IAM, or non-EKS resources in the same tool
- Private cluster creation has limitations (initially creates public endpoint, then disables it)
- Does not support standard support tier cluster creation
- Less composable than Terraform modules -- harder to integrate with broader infrastructure
- YAML config format is less expressive than HCL for conditionals and loops

### 3. AWS CDK (TypeScript/Python)

| Aspect | Assessment |
|--------|-----------|
| **Maturity** | 6+ years, first-party AWS tool. |
| **EKS Support** | L2/L3 constructs for EKS. `aws-eks` module handles cluster, node groups, add-ons. |
| **State Management** | CloudFormation-backed. No separate state file. |
| **Multi-Cloud** | AWS-only (though cdktf existed, it was deprecated in December 2025). |
| **Community** | Growing but smaller than Terraform. AWS-focused. |
| **Learning Curve** | Higher -- requires knowledge of CDK concepts (constructs, stacks, aspects) plus a programming language. |
| **CI/CD Integration** | `cdk synth` + `cdk deploy` workflow. Less mature than Terraform's CI ecosystem. |

**Pros:**
- Full programming language (TypeScript, Python, Go, Java) for infrastructure
- L3 constructs encapsulate AWS best practices
- Type safety and IDE autocomplete reduce errors
- CloudFormation deployment means native AWS state management
- Good for teams already using TypeScript/Python extensively
- `cdk diff` provides preview before deployment

**Cons:**
- **AWS-only** -- cannot manage non-AWS resources (Kubernetes manifests, external DNS, etc.)
- CloudFormation has a 500-resource limit per stack (can be hit with complex EKS setups)
- CloudFormation rollbacks can leave resources in inconsistent states
- Steeper learning curve than HCL for infrastructure-as-code newcomers
- CDKTF (CDK for Terraform) was deprecated in December 2025, reducing CDK's reach
- Synthesized CloudFormation templates are verbose and harder to review
- Debugging CloudFormation failures requires understanding both CDK and CloudFormation

### 4. Pulumi (Go/TypeScript/Python)

| Aspect | Assessment |
|--------|-----------|
| **Maturity** | 7+ years, well-funded company. |
| **EKS Support** | Full AWS provider + Pulumi EKS component. |
| **State Management** | Pulumi Cloud (SaaS) or self-hosted backend (S3). |
| **Multi-Cloud** | 150+ providers including AWS, Azure, GCP, Kubernetes. |
| **Community** | Growing rapidly but smaller than Terraform. Good documentation. |
| **Learning Curve** | Uses familiar programming languages, but Pulumi-specific concepts (stacks, inputs/outputs, component resources) add overhead. |
| **CI/CD Integration** | `pulumi preview` + `pulumi up`. GitHub Actions support available. |

**Pros:**
- Real programming languages (Go, TypeScript, Python, C#) -- no new DSL to learn
- Multi-cloud support comparable to Terraform
- Strong typing catches errors at compile time
- `pulumi preview` provides change preview
- Pulumi AI can generate configurations from natural language
- Good Kubernetes integration (can manage cluster and workloads in one program)

**Cons:**
- Smaller community means fewer ready-made examples and modules
- Default state management requires Pulumi Cloud (SaaS) -- self-hosted backend is possible but adds setup
- Less hiring pool familiarity compared to Terraform/HCL
- The project is Go-based, but Pulumi's Go SDK is less polished than its TypeScript SDK
- Risk of over-engineering infrastructure with programming language features (loops, abstractions)
- Migration path from Pulumi is harder than from Terraform/OpenTofu

---

## Comparison Matrix

| Criterion | OpenTofu/Terraform | eksctl | AWS CDK | Pulumi |
|-----------|-------------------|--------|---------|--------|
| Time to first cluster | Medium | **Fast** | Medium | Medium |
| Preview before apply | **Yes** (`plan`) | No | Yes (`diff`) | Yes (`preview`) |
| State management | Explicit (S3) | CloudFormation | CloudFormation | Pulumi Cloud/S3 |
| Multi-cloud | **Yes** (3,900+) | No | No | Yes (150+) |
| EKS module maturity | **Best** (721K/week) | Good | Good | Good |
| Community size | **Largest** | Medium | Medium | Growing |
| Composability | **High** (modules) | Low | Medium | High |
| License | MPL-2.0 (OpenTofu) | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| Learning curve | Low-Medium | **Low** | Medium-High | Medium |
| VPC/networking control | **Full** | Limited | Full | Full |
| Kubernetes resource mgmt | Via provider | Limited | Limited | **Native** |

---

## Project-Specific Recommendation

For the PRECINCT, OpenTofu/Terraform is the strongest choice because:

1. **The project will grow.** Beyond EKS, we need VPC with NetworkPolicy-capable CNI, IAM roles for SPIRE workload identity, S3 for state/artifacts, and potentially ALB/NLB for ingress. Terraform handles all of these in one codebase.

2. **SPIRE integration requires precise networking.** SPIRE server/agent communication, workload attestation, and OIDC federation all require careful VPC, security group, and IAM configuration. Terraform's explicit resource model makes this auditable.

3. **The docker-compose stack maps cleanly to Terraform.** Each service in our `docker-compose.yml` (spire-server, spire-agent, otel-collector, phoenix, mcp-security-gateway) becomes a Kubernetes Deployment + Service, and Terraform can manage the Kubernetes resources alongside the cluster.

4. **Reproducibility matters for a reference architecture.** Others will clone this and deploy it. `tofu plan` + `tofu apply` is the most widely understood IaC workflow. eksctl's lack of plan mode makes it harder to review changes before applying.

5. **Module ecosystem.** The `terraform-aws-modules/eks` module (v21.15.1) handles managed node groups, OIDC provider, Karpenter, and add-ons. Combined with `terraform-aws-modules/vpc`, we get a production-quality foundation.

### Suggested Project Structure

```
deploy/terraform/
  main.tf              # Root module: EKS cluster, VPC, IAM
  variables.tf         # Input variables (region, cluster name, node sizing)
  outputs.tf           # Cluster endpoint, kubeconfig, OIDC provider ARN
  versions.tf          # Provider and OpenTofu version constraints
  backend.tf           # S3 remote state configuration
  terraform.tfvars     # Environment-specific values (not committed)
  modules/             # Custom modules if needed (e.g., SPIRE IAM roles)
```

### Recommended Approach for Cluster

Use **EKS with managed node groups** (not Auto Mode) for this project:

- **Managed node groups** give full control over instance types and pricing while AWS handles node lifecycle.
- **EKS Auto Mode** adds a per-instance surcharge and is better suited for production workloads where operational simplicity outweighs cost control.
- For a reference implementation, we want cost predictability and the ability to use Spot instances aggressively.

---

## Required AWS Permissions

The IAM principal running OpenTofu/Terraform requires the following permissions. These are organized by the lifecycle phase and AWS service.

### Cluster Provisioning (Required)

**EKS:**
- `eks:CreateCluster`, `eks:DeleteCluster`, `eks:DescribeCluster`, `eks:UpdateClusterConfig`, `eks:UpdateClusterVersion`
- `eks:TagResource`, `eks:UntagResource`, `eks:ListTagsForResource`
- `eks:CreateNodegroup`, `eks:DeleteNodegroup`, `eks:DescribeNodegroup`, `eks:UpdateNodegroupConfig`, `eks:UpdateNodegroupVersion`
- `eks:CreateAddon`, `eks:DeleteAddon`, `eks:DescribeAddon`, `eks:DescribeAddonVersions`, `eks:UpdateAddon`
- `eks:AssociateIdentityProviderConfig`, `eks:DescribeIdentityProviderConfig`
- `eks:CreateAccessEntry`, `eks:DeleteAccessEntry`, `eks:DescribeAccessEntry`, `eks:ListAccessEntries`
- `eks:AssociateAccessPolicy`, `eks:DisassociateAccessPolicy`

**EC2 (VPC/Networking):**
- `ec2:CreateVpc`, `ec2:DeleteVpc`, `ec2:DescribeVpcs`, `ec2:ModifyVpcAttribute`
- `ec2:CreateSubnet`, `ec2:DeleteSubnet`, `ec2:DescribeSubnets`
- `ec2:CreateInternetGateway`, `ec2:DeleteInternetGateway`, `ec2:AttachInternetGateway`, `ec2:DetachInternetGateway`
- `ec2:CreateNatGateway`, `ec2:DeleteNatGateway`, `ec2:DescribeNatGateways`
- `ec2:AllocateAddress`, `ec2:ReleaseAddress`, `ec2:DescribeAddresses`
- `ec2:CreateRouteTable`, `ec2:DeleteRouteTable`, `ec2:CreateRoute`, `ec2:DeleteRoute`, `ec2:AssociateRouteTable`, `ec2:DisassociateRouteTable`
- `ec2:CreateSecurityGroup`, `ec2:DeleteSecurityGroup`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupEgress`, `ec2:RevokeSecurityGroupIngress`, `ec2:RevokeSecurityGroupEgress`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`
- `ec2:DescribeAvailabilityZones`, `ec2:DescribeInstances`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeDhcpOptions`
- `ec2:CreateTags`, `ec2:DeleteTags`, `ec2:DescribeTags`
- `ec2:CreateLaunchTemplate`, `ec2:DeleteLaunchTemplate`, `ec2:DescribeLaunchTemplates`, `ec2:DescribeLaunchTemplateVersions`

**IAM:**
- `iam:CreateRole`, `iam:DeleteRole`, `iam:GetRole`, `iam:PassRole`, `iam:TagRole`
- `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`
- `iam:CreatePolicy`, `iam:DeletePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`
- `iam:CreateOpenIDConnectProvider`, `iam:DeleteOpenIDConnectProvider`, `iam:GetOpenIDConnectProvider`, `iam:TagOpenIDConnectProvider`
- `iam:CreateServiceLinkedRole` (for `eks.amazonaws.com` and `eks-nodegroup.amazonaws.com`)
- `iam:CreateInstanceProfile`, `iam:DeleteInstanceProfile`, `iam:AddRoleToInstanceProfile`, `iam:RemoveRoleFromInstanceProfile`

**CloudFormation** (if using eksctl fallback):
- `cloudformation:*` (eksctl generates CloudFormation stacks)

**S3 (for Terraform state):**
- `s3:CreateBucket`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`
- `s3:GetBucketVersioning`, `s3:PutBucketVersioning`

**DynamoDB (for state locking):**
- `dynamodb:CreateTable`, `dynamodb:DeleteTable`, `dynamodb:DescribeTable`
- `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:DeleteItem`

**KMS (optional, for encryption):**
- `kms:CreateKey`, `kms:DescribeKey`, `kms:CreateAlias`, `kms:DeleteAlias`
- `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`

**CloudWatch Logs:**
- `logs:CreateLogGroup`, `logs:DeleteLogGroup`, `logs:DescribeLogGroups`, `logs:PutRetentionPolicy`, `logs:TagLogGroup`

### Cluster IAM Roles (Created by Terraform)

The cluster itself requires two IAM roles that Terraform will create:

1. **EKS Cluster Role** -- attached policies:
   - `AmazonEKSClusterPolicy`
   - Minimal custom policy: `ec2:CreateTags`, `ec2:DescribeInstances`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeVpcs`, `ec2:DescribeDhcpOptions`, `ec2:DescribeAvailabilityZones`, `ec2:DescribeInstanceTopology`, `kms:DescribeKey`

2. **EKS Node Role** -- attached policies:
   - `AmazonEKSWorkerNodePolicy`
   - `AmazonEC2ContainerRegistryPullOnly`
   - `AmazonEKS_CNI_Policy` (for VPC CNI plugin)

### Practical Approach to Permission Discovery

For the exact minimum permissions needed for a specific Terraform configuration, use [`iamlive`](https://github.com/iann0036/iamlive) in proxy mode during `tofu plan` and `tofu apply`. This captures the actual API calls made and generates a minimum IAM policy.

```bash
# Run iamlive as a proxy
iamlive --mode proxy --output-file min-policy.json

# In another terminal, run tofu with the proxy
HTTP_PROXY=http://127.0.0.1:10080 HTTPS_PROXY=http://127.0.0.1:10080 tofu apply
```

---

## Baseline Cost Estimate (us-west-2, Minimal Development Cluster)

### Scenario: Minimal Development Cluster

| Component | Specification | Monthly Cost (USD) |
|-----------|--------------|-------------------|
| **EKS Control Plane** | 1 cluster, standard support | $73.00 |
| **Worker Nodes** | 3x t3.medium On-Demand (2 vCPU, 4 GiB each) | $91.10 |
| **EBS Volumes** | 3x 20 GiB gp3 (root volumes) | $4.80 |
| **NAT Gateway** | 1x NAT Gateway (single AZ for development) | $32.85 |
| **NAT Data Processing** | ~50 GiB/month estimated | $2.25 |
| **S3 (Terraform state)** | Negligible | $0.00 |
| **DynamoDB (state lock)** | On-demand, minimal usage | $0.00 |
| **ALB (if used for ingress)** | 1x Application Load Balancer | $16.43 |
| | | |
| **Total (without ALB)** | | **~$204/month** |
| **Total (with ALB)** | | **~$220/month** |

### Pricing Breakdown

- **EKS Control Plane:** $0.10/hour x 730 hours = $73.00/month (standard support). Extended support (for older Kubernetes versions past standard 14-month window) is $0.60/hour = $438/month -- avoid by staying on supported versions.
- **t3.medium instances:** $0.0416/hour x 730 hours = $30.37/month per instance. 3 instances across availability zones for basic HA = $91.10/month.
- **gp3 EBS:** $0.08/GB/month x 20 GiB x 3 nodes = $4.80/month.
- **NAT Gateway:** $0.045/hour x 730 hours = $32.85/month + $0.045/GiB processed.
- **ALB:** $0.0225/hour x 730 hours = $16.43/month base + LCU charges (minimal for development).

### Cost Optimization Strategies

| Strategy | Savings | Tradeoff |
|----------|---------|----------|
| **Spot Instances** for non-critical workloads | 60-90% on compute | Interruptions possible (use for agents, not gateway) |
| **Single NAT Gateway** (not per-AZ) | ~$65/month | Single point of failure for outbound traffic |
| **t3.small** instead of t3.medium | ~$45/month | 2 GiB RAM per node may be tight |
| **Scheduled scaling** (scale to 0 off-hours) | ~50% on compute | Cluster startup latency when scaling up |
| **Savings Plans** (1-year commitment) | ~30% on compute | Commitment required |

### When to Consider EKS Auto Mode

EKS Auto Mode simplifies node management but adds a surcharge (~$0.012/hour for m5.large, on top of the EC2 cost). For a development cluster with 3 nodes, this adds ~$26/month. Consider Auto Mode when:
- Operational simplicity is more important than cost
- The team does not want to manage node groups, AMIs, or scaling policies
- Production deployment where node lifecycle management is a burden

For this project, managed node groups with explicit instance types provide better cost control and transparency.

---

## Decision Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **IaC Tool** | OpenTofu | Open-source, full Terraform ecosystem compatibility, no BSL concerns |
| **EKS Module** | `terraform-aws-modules/eks` v21.x | Battle-tested, 134M+ downloads, covers OIDC/node groups/add-ons |
| **Compute Strategy** | Managed node groups (t3.medium) | Cost-predictable, full control, Spot-compatible |
| **Networking** | `terraform-aws-modules/vpc` | Handles public/private subnets, NAT, tagging for EKS |
| **State Backend** | S3 + DynamoDB | Standard, cheap, supports locking |
| **Region** | us-west-2 (Oregon) | As specified; good pricing, full EKS feature availability |

### Next Steps (for story RFA-9fv.2)

1. Create S3 bucket and DynamoDB table for Terraform state (can be done via CLI or a bootstrap Terraform config)
2. Write `deploy/terraform/` Terraform configuration using the recommended modules
3. Validate with `tofu plan` in dry-run mode
4. Apply to create the cluster
5. Verify with `kubectl get nodes` and deploy a test workload

---

## Sources

- [Terraform vs Pulumi vs AWS CDK: 2025 Decision Framework](https://sanj.dev/post/terraform-pulumi-aws-cdk-2025-decision-framework)
- [AWS CDK vs Terraform: The Complete 2026 Comparison](https://dev.to/aws-builders/aws-cdk-vs-terraform-the-complete-2026-comparison-3b4p)
- [terraform-aws-modules/eks on Terraform Registry](https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest)
- [Amazon EKS Pricing](https://aws.amazon.com/eks/pricing/)
- [EKS Pricing: A Complete Breakdown (2025 Guide)](https://www.devzero.io/blog/eks-pricing)
- [Amazon EKS Cluster IAM Role](https://docs.aws.amazon.com/eks/latest/userguide/cluster-iam-role.html)
- [eksctl Minimum IAM Policies](https://eksctl.io/usage/minimum-iam-policies/)
- [Amazon EKS Guide 2026](https://sedai.io/blog/guide-amazon-eks-managed-kubernetes-aws)
- [OpenTofu vs Terraform Comparison](https://spacelift.io/blog/opentofu-vs-terraform)
- [Top 10 IaC Tools for DevOps in 2026](https://dev.to/inboryn_99399f96579fcd705/top-10-iac-tools-for-devops-in-2026-which-one-wins-for-multi-cloud-terraform-pulumi-opentofu-hfb)
- [EKS Auto Mode](https://aws.amazon.com/eks/auto-mode/)
- [AWS EKS Pricing Calculator 2025](https://clustercost.com/blog/aws-eks-pricing-calculator-2025/)
