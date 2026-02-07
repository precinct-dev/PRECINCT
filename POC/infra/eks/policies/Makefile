# ------------------------------------------------------------------------------
# NetworkPolicy Deployment Makefile
# Story: RFA-9fv.4
#
# Targets for deploying and managing NetworkPolicies on EKS.
# Deployment order: default-deny -> explicit allow rules
#
# Prerequisites:
#   - kubectl configured with EKS cluster context
#   - Gateway and tools namespaces created (deploy gateway and mcp-server first)
#   - NetworkPolicy-capable CNI (Calico, Cilium) installed in EKS
#   - kubeconform installed (brew install kubeconform) for offline validation
# ------------------------------------------------------------------------------
.PHONY: help deploy undeploy verify dry-run

KUBECTL ?= kubectl

help: ## Show this help message
	@echo "NetworkPolicy Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy (applies default-deny then allow rules)"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: ## Deploy all NetworkPolicies (default-deny + explicit allow)
	@echo "=== Deploying NetworkPolicies ==="
	@echo "Step 1: Applying default-deny policies..."
	$(KUBECTL) apply -f default-deny.yaml
	@echo "Step 2: Applying gateway allow rules..."
	$(KUBECTL) apply -f gateway-allow.yaml
	@echo "Step 3: Applying MCP server allow rules..."
	$(KUBECTL) apply -f mcp-server-allow.yaml
	@echo ""
	@echo "NetworkPolicies deployed. Run 'make verify' to check."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify NetworkPolicies are applied in both namespaces
	@echo "=== Gateway Namespace NetworkPolicies ==="
	$(KUBECTL) -n gateway get networkpolicies
	@echo ""
	@echo "=== Tools Namespace NetworkPolicies ==="
	$(KUBECTL) -n tools get networkpolicies
	@echo ""
	@echo "=== Policy Details (gateway) ==="
	$(KUBECTL) -n gateway describe networkpolicy default-deny-all 2>/dev/null || echo "(not found)"
	@echo ""
	$(KUBECTL) -n gateway describe networkpolicy gateway-allow-ingress 2>/dev/null || echo "(not found)"
	@echo ""
	$(KUBECTL) -n gateway describe networkpolicy gateway-allow-egress 2>/dev/null || echo "(not found)"
	@echo ""
	@echo "=== Policy Details (tools) ==="
	$(KUBECTL) -n tools describe networkpolicy default-deny-all 2>/dev/null || echo "(not found)"
	@echo ""
	$(KUBECTL) -n tools describe networkpolicy mcp-server-allow-ingress 2>/dev/null || echo "(not found)"
	@echo ""
	$(KUBECTL) -n tools describe networkpolicy mcp-server-allow-egress 2>/dev/null || echo "(not found)"

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# ---------------------------------------------------------------------------

dry-run: ## Validate all NetworkPolicy manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			default-deny.yaml \
			gateway-allow.yaml \
			mcp-server-allow.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in default-deny.yaml gateway-allow.yaml mcp-server-allow.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All NetworkPolicy manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all NetworkPolicies
	@echo "=== Removing NetworkPolicies ==="
	-$(KUBECTL) delete -f mcp-server-allow.yaml --ignore-not-found
	-$(KUBECTL) delete -f gateway-allow.yaml --ignore-not-found
	-$(KUBECTL) delete -f default-deny.yaml --ignore-not-found
	@echo "NetworkPolicies removed."
