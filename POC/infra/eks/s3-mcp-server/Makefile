# ------------------------------------------------------------------------------
# S3 MCP Tool Server Deployment Makefile
# Story: RFA-9fv.5
#
# Targets for deploying and managing the S3 MCP tool server on EKS.
# Deployment order: RBAC -> ConfigMap -> Deployment -> Service -> NetworkPolicy
#
# Prerequisites:
#   - kubectl configured with EKS cluster context
#   - tools namespace exists (created by mcp-server deployment)
#   - SPIRE deployed (make -C ../spire deploy)
#   - IAM role created (terraform apply in this directory)
#   - kubeconform installed (brew install kubeconform) for offline validation
# ------------------------------------------------------------------------------
.PHONY: help deploy undeploy verify dry-run status logs

KUBECTL ?= kubectl
NAMESPACE := tools

help: ## Show this help message
	@echo "S3 MCP Tool Server Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy (runs all steps in order)"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: ## Deploy all S3 MCP tool server components
	@echo "=== Deploying S3 MCP Tool Server ==="
	$(KUBECTL) apply -f s3-mcp-server-rbac.yaml
	$(KUBECTL) apply -f s3-mcp-server-configmap.yaml
	$(KUBECTL) apply -f s3-mcp-server-deployment.yaml
	$(KUBECTL) apply -f s3-mcp-server-service.yaml
	$(KUBECTL) apply -f s3-mcp-server-networkpolicy.yaml
	@echo "Waiting for S3 MCP server pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/s3-mcp-server --timeout=120s
	@echo "S3 MCP tool server deployed."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify S3 MCP server health (pods, services)
	@echo "=== S3 MCP Server Pod Health ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=s3-mcp-server
	@echo ""
	@echo "=== S3 MCP Server Service ==="
	$(KUBECTL) -n $(NAMESPACE) get svc s3-mcp-server
	@echo ""
	@echo "=== S3 MCP Server Logs (last 10 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=s3-mcp-server --tail=10 2>/dev/null || echo "(no logs yet)"

status: ## Show pod and service status
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=s3-mcp-server -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc s3-mcp-server
	@echo ""
	@echo "=== Deployments ==="
	$(KUBECTL) -n $(NAMESPACE) get deployment s3-mcp-server

logs: ## Tail S3 MCP server logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=s3-mcp-server

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			s3-mcp-server-rbac.yaml \
			s3-mcp-server-configmap.yaml \
			s3-mcp-server-deployment.yaml \
			s3-mcp-server-service.yaml \
			s3-mcp-server-networkpolicy.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in s3-mcp-server-rbac.yaml s3-mcp-server-configmap.yaml \
			s3-mcp-server-deployment.yaml s3-mcp-server-service.yaml \
			s3-mcp-server-networkpolicy.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All S3 MCP server manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all S3 MCP tool server resources
	@echo "=== Removing S3 MCP Tool Server ==="
	-$(KUBECTL) delete -f s3-mcp-server-networkpolicy.yaml --ignore-not-found
	-$(KUBECTL) delete -f s3-mcp-server-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f s3-mcp-server-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f s3-mcp-server-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f s3-mcp-server-rbac.yaml --ignore-not-found
	@echo "S3 MCP tool server removed."
