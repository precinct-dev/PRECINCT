# ------------------------------------------------------------------------------
# MCP Tool Server Deployment Makefile
# Story: RFA-9fv.4
#
# Targets for deploying and managing MCP tool servers on EKS.
# Deployment order: namespace/RBAC -> deployment -> service
#
# Prerequisites:
#   - kubectl configured with EKS cluster context
#   - SPIRE deployed (make -C ../spire deploy)
#   - kubeconform installed (brew install kubeconform) for offline validation
# ------------------------------------------------------------------------------
.PHONY: help deploy undeploy verify dry-run status logs

KUBECTL ?= kubectl
NAMESPACE := tools

help: ## Show this help message
	@echo "MCP Tool Server Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy (runs all steps in order)"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: ## Deploy all MCP tool server components
	@echo "=== Deploying MCP Tool Server ==="
	$(KUBECTL) apply -f mcp-server-namespace.yaml
	$(KUBECTL) apply -f mcp-server-rbac.yaml
	$(KUBECTL) apply -f mcp-server-deployment.yaml
	$(KUBECTL) apply -f mcp-server-service.yaml
	@echo "Waiting for MCP server pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/mcp-server --timeout=120s
	@echo "MCP tool server deployed."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify MCP server health (pods, services)
	@echo "=== MCP Server Pod Health ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=mcp-server
	@echo ""
	@echo "=== MCP Server Service ==="
	$(KUBECTL) -n $(NAMESPACE) get svc mcp-server
	@echo ""
	@echo "=== MCP Server Logs (last 10 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=mcp-server --tail=10 2>/dev/null || echo "(no logs yet)"

status: ## Show pod and service status
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc
	@echo ""
	@echo "=== Deployments ==="
	$(KUBECTL) -n $(NAMESPACE) get deployments

logs: ## Tail MCP server logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=mcp-server

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			mcp-server-namespace.yaml \
			mcp-server-rbac.yaml \
			mcp-server-deployment.yaml \
			mcp-server-service.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in mcp-server-namespace.yaml mcp-server-rbac.yaml \
			mcp-server-deployment.yaml mcp-server-service.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All MCP server manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all MCP tool server resources
	@echo "=== Removing MCP Tool Server ==="
	-$(KUBECTL) delete -f mcp-server-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f mcp-server-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f mcp-server-rbac.yaml --ignore-not-found
	@echo "Deleting namespace..."
	-$(KUBECTL) delete -f mcp-server-namespace.yaml --ignore-not-found
	@echo "MCP tool server removed."
