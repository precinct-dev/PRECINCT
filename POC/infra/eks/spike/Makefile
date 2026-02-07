# ------------------------------------------------------------------------------
# SPIKE Nexus Deployment Makefile
# Story: RFA-9fv.3
#
# Targets for deploying and managing SPIKE Nexus on EKS.
# Prerequisite: SPIRE must be deployed first (make -C ../spire deploy).
# ------------------------------------------------------------------------------
.PHONY: help deploy undeploy verify dry-run status logs

KUBECTL ?= kubectl
NAMESPACE := spike-system

help: ## Show this help message
	@echo "SPIKE Nexus Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Prerequisite: SPIRE must be deployed first (make -C ../spire deploy)"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: ## Deploy SPIKE Nexus (namespace, RBAC, ConfigMap, Deployment, Service)
	@echo "=== Deploying SPIKE Nexus ==="
	$(KUBECTL) apply -f namespace.yaml
	$(KUBECTL) apply -f nexus-rbac.yaml
	$(KUBECTL) apply -f nexus-configmap.yaml
	$(KUBECTL) apply -f nexus-deployment.yaml
	$(KUBECTL) apply -f nexus-service.yaml
	@echo "Waiting for SPIKE Nexus pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/spike-nexus --timeout=120s
	@echo "SPIKE Nexus deployed."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify SPIKE Nexus health
	@echo "=== SPIKE Nexus Pod Status ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=spike-nexus
	@echo ""
	@echo "=== SPIKE Nexus Service ==="
	$(KUBECTL) -n $(NAMESPACE) get svc spike-nexus
	@echo ""
	@echo "=== SPIKE Nexus Logs (last 20 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=spike-nexus --tail=20

status: ## Show pod status for SPIKE components
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

logs: ## Tail SPIKE Nexus logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=spike-nexus

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			namespace.yaml nexus-rbac.yaml nexus-configmap.yaml \
			nexus-deployment.yaml nexus-service.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in namespace.yaml nexus-rbac.yaml nexus-configmap.yaml \
			nexus-deployment.yaml nexus-service.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All SPIKE manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all SPIKE resources
	@echo "=== Removing SPIKE Nexus ==="
	-$(KUBECTL) delete -f nexus-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f namespace.yaml --ignore-not-found
	@echo "SPIKE Nexus removed."
