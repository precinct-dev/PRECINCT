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

deploy: ## Deploy SPIKE keeper+nexus runtime surfaces (jobs remain operator-triggered)
	@echo "=== Deploying SPIKE keeper+nexus runtime surfaces ==="
	$(KUBECTL) apply -f namespace.yaml
	$(KUBECTL) apply -f keeper-rbac.yaml
	$(KUBECTL) apply -f nexus-rbac.yaml
	$(KUBECTL) apply -f bootstrap-rbac.yaml
	$(KUBECTL) apply -f seeder-rbac.yaml
	$(KUBECTL) apply -f nexus-configmap.yaml
	$(KUBECTL) apply -f nexus-pvc.yaml
	$(KUBECTL) apply -f keeper-service.yaml
	$(KUBECTL) apply -f keeper-deployment.yaml
	$(KUBECTL) apply -f keeper-2-service.yaml
	$(KUBECTL) apply -f keeper-2-deployment.yaml
	$(KUBECTL) apply -f keeper-3-service.yaml
	$(KUBECTL) apply -f keeper-3-deployment.yaml
	$(KUBECTL) apply -f nexus-deployment.yaml
	$(KUBECTL) apply -f nexus-service.yaml
	$(KUBECTL) apply -f spike-networkpolicies.yaml
	@echo "Waiting for SPIKE Keeper pods to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/spike-keeper --timeout=120s
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/spike-keeper-2 --timeout=120s
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/spike-keeper-3 --timeout=120s
	@echo "Waiting for SPIKE Nexus pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/spike-nexus --timeout=120s
	@echo "SPIKE keeper+nexus runtime surfaces deployed."

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

dry-run: ## Validate SPIKE keeper+nexus manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			namespace.yaml keeper-rbac.yaml nexus-rbac.yaml bootstrap-rbac.yaml seeder-rbac.yaml \
			nexus-configmap.yaml nexus-pvc.yaml keeper-service.yaml keeper-deployment.yaml \
			keeper-2-service.yaml keeper-2-deployment.yaml keeper-3-service.yaml keeper-3-deployment.yaml \
			nexus-deployment.yaml nexus-service.yaml bootstrap-job.yaml seeder-job.yaml spike-networkpolicies.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in namespace.yaml keeper-rbac.yaml nexus-rbac.yaml bootstrap-rbac.yaml seeder-rbac.yaml \
			nexus-configmap.yaml nexus-pvc.yaml keeper-service.yaml keeper-deployment.yaml \
			keeper-2-service.yaml keeper-2-deployment.yaml keeper-3-service.yaml keeper-3-deployment.yaml \
			nexus-deployment.yaml nexus-service.yaml bootstrap-job.yaml seeder-job.yaml spike-networkpolicies.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All SPIKE manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove SPIKE keeper+nexus runtime surfaces
	@echo "=== Removing SPIKE keeper+nexus runtime surfaces ==="
	-$(KUBECTL) delete -f spike-networkpolicies.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-3-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-3-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-2-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-2-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-pvc.yaml --ignore-not-found
	-$(KUBECTL) delete -f seeder-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f bootstrap-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f keeper-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f nexus-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f namespace.yaml --ignore-not-found
	@echo "SPIKE keeper+nexus runtime surfaces removed."
