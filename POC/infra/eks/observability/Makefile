# ------------------------------------------------------------------------------
# Observability Stack Makefile
# Story: RFA-9fv.7
#
# Targets for deploying and managing the observability stack on EKS:
#   - OTEL Collector (trace/metric/log pipeline)
#   - Phoenix (trace visualization)
#   - Audit S3 sink configuration
#   - NetworkPolicies
#
# Deployment order:
#   1. Namespace
#   2. RBAC (ServiceAccounts)
#   3. ConfigMaps
#   4. Deployments + Services
#   5. NetworkPolicies
#
# Prerequisites:
#   - kubectl configured with EKS cluster context
#   - Gateway deployed (make -C ../gateway deploy)
#   - kubeconform installed (brew install kubeconform) for offline validation
#   - For audit S3: tofu apply in audit/ directory first
# ------------------------------------------------------------------------------
.PHONY: help deploy deploy-namespace deploy-rbac deploy-configs deploy-otel \
        deploy-phoenix deploy-policies deploy-audit undeploy verify dry-run \
        status logs-otel logs-phoenix

KUBECTL ?= kubectl
NAMESPACE := observability

help: ## Show this help message
	@echo "Observability Stack -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy (runs all steps in order)"

# ---------------------------------------------------------------------------
# Full deployment (all components)
# ---------------------------------------------------------------------------

deploy: deploy-namespace deploy-rbac deploy-configs deploy-phoenix deploy-otel deploy-policies ## Deploy all observability components
	@echo ""
	@echo "Observability stack deployment complete."
	@echo "Run 'make verify' to check health."
	@echo ""
	@echo "Phoenix UI: kubectl -n $(NAMESPACE) get svc phoenix -o jsonpath='{.spec.ports[?(@.name==\"http-ui\")].nodePort}'"
	@echo "  Access via: http://<node-ip>:<nodePort>"

# ---------------------------------------------------------------------------
# Individual deployment targets
# ---------------------------------------------------------------------------

deploy-namespace: ## Create observability namespace
	@echo "=== Deploying Observability Namespace ==="
	$(KUBECTL) apply -f observability-namespace.yaml

deploy-rbac: deploy-namespace ## Create ServiceAccounts
	@echo "=== Deploying ServiceAccounts ==="
	$(KUBECTL) apply -f otel-collector/otel-collector-rbac.yaml
	$(KUBECTL) apply -f phoenix/phoenix-rbac.yaml
	$(KUBECTL) apply -f audit/audit-s3-rbac.yaml

deploy-configs: deploy-namespace ## Deploy ConfigMaps
	@echo "=== Deploying ConfigMaps ==="
	$(KUBECTL) apply -f otel-collector/otel-collector-configmap.yaml
	$(KUBECTL) apply -f audit/audit-s3-config.yaml

deploy-otel: deploy-configs ## Deploy OTEL Collector (deployment + service)
	@echo "=== Deploying OTEL Collector ==="
	$(KUBECTL) apply -f otel-collector/otel-collector-deployment.yaml
	$(KUBECTL) apply -f otel-collector/otel-collector-service.yaml
	@echo "Waiting for otel-collector pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/otel-collector --timeout=120s
	@echo "OTEL Collector deployed."

deploy-phoenix: deploy-configs ## Deploy Phoenix (PVC + deployment + service)
	@echo "=== Deploying Phoenix ==="
	$(KUBECTL) apply -f phoenix/phoenix-deployment.yaml
	$(KUBECTL) apply -f phoenix/phoenix-service.yaml
	@echo "Waiting for phoenix pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/phoenix --timeout=120s
	@echo "Phoenix deployed."

deploy-policies: deploy-namespace ## Apply NetworkPolicies
	@echo "=== Deploying NetworkPolicies ==="
	$(KUBECTL) apply -f observability-policies.yaml

deploy-audit: ## Apply audit S3 IAM resources (requires tofu)
	@echo "=== Deploying Audit S3 IAM Resources ==="
	@echo "Running tofu apply in audit/ directory..."
	cd audit && tofu init && tofu apply -auto-approve
	@echo ""
	@echo "Update audit-s3-rbac.yaml with the IAM role ARN from tofu output:"
	@cd audit && tofu output audit_iam_role_arn

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify observability stack health
	@echo "=== Namespace ==="
	$(KUBECTL) get namespace $(NAMESPACE) --show-labels
	@echo ""
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc
	@echo ""
	@echo "=== PersistentVolumeClaims ==="
	$(KUBECTL) -n $(NAMESPACE) get pvc
	@echo ""
	@echo "=== ConfigMaps ==="
	$(KUBECTL) -n $(NAMESPACE) get configmaps
	@echo ""
	@echo "=== NetworkPolicies ==="
	$(KUBECTL) -n $(NAMESPACE) get networkpolicies
	@echo ""
	@echo "=== OTEL Collector Logs (last 5 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=otel-collector --tail=5 2>/dev/null || echo "(no logs yet)"
	@echo ""
	@echo "=== Phoenix Logs (last 5 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=phoenix --tail=5 2>/dev/null || echo "(no logs yet)"

status: ## Show pod and service status
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc
	@echo ""
	@echo "=== Deployments ==="
	$(KUBECTL) -n $(NAMESPACE) get deployments

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

logs-otel: ## Tail OTEL Collector logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=otel-collector

logs-phoenix: ## Tail Phoenix logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=phoenix

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			observability-namespace.yaml \
			otel-collector/otel-collector-rbac.yaml \
			otel-collector/otel-collector-configmap.yaml \
			otel-collector/otel-collector-deployment.yaml \
			otel-collector/otel-collector-service.yaml \
			phoenix/phoenix-rbac.yaml \
			phoenix/phoenix-deployment.yaml \
			phoenix/phoenix-service.yaml \
			audit/audit-s3-config.yaml \
			audit/audit-s3-rbac.yaml \
			observability-policies.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in observability-namespace.yaml \
			otel-collector/otel-collector-rbac.yaml \
			otel-collector/otel-collector-configmap.yaml \
			otel-collector/otel-collector-deployment.yaml \
			otel-collector/otel-collector-service.yaml \
			phoenix/phoenix-rbac.yaml \
			phoenix/phoenix-deployment.yaml \
			phoenix/phoenix-service.yaml \
			audit/audit-s3-config.yaml \
			audit/audit-s3-rbac.yaml \
			observability-policies.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All observability manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all observability resources
	@echo "=== Removing Observability Stack ==="
	-$(KUBECTL) delete -f observability-policies.yaml --ignore-not-found
	-$(KUBECTL) delete -f otel-collector/otel-collector-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f otel-collector/otel-collector-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f phoenix/phoenix-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f phoenix/phoenix-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f otel-collector/otel-collector-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f audit/audit-s3-config.yaml --ignore-not-found
	-$(KUBECTL) delete -f audit/audit-s3-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f otel-collector/otel-collector-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f phoenix/phoenix-rbac.yaml --ignore-not-found
	@echo "Deleting namespace..."
	-$(KUBECTL) delete -f observability-namespace.yaml --ignore-not-found
	@echo "Observability stack removed."
	@echo ""
	@echo "NOTE: Audit S3 bucket and IAM resources are NOT removed."
	@echo "To remove: cd audit && tofu destroy"
