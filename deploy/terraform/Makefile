.PHONY: help init plan apply destroy validate fmt clean

# Default target
help: ## Show this help message
	@echo "EKS Cluster IaC -- OpenTofu/Terraform Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make init    # Initialize providers and modules"
	@echo "  make plan    # Preview changes"
	@echo "  make apply   # Create/update the cluster"
	@echo "  make destroy # Tear down the cluster"

init: ## Initialize OpenTofu/Terraform (download providers and modules)
	tofu init -backend=false

plan: ## Preview infrastructure changes without applying
	tofu plan

apply: ## Create or update the EKS cluster (requires confirmation)
	tofu apply

destroy: ## Destroy the EKS cluster and all associated resources
	tofu destroy

validate: ## Validate HCL syntax and configuration
	tofu validate

fmt: ## Check HCL formatting (fails if files need reformatting)
	tofu fmt -check

fmt-fix: ## Auto-fix HCL formatting
	tofu fmt
