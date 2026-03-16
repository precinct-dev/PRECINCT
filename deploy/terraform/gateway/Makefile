# ------------------------------------------------------------------------------
# Gateway Deployment Makefile
# Story: RFA-9fv.4
#
# Targets for deploying and managing the PRECINCT Gateway on EKS.
# Deployment order: namespace/RBAC -> ConfigMap -> deployment -> service
#
# Prerequisites:
#   - kubectl configured with EKS cluster context
#   - SPIRE deployed (make -C ../spire deploy)
#   - kubeconform installed (brew install kubeconform) for offline validation
# ------------------------------------------------------------------------------
.PHONY: help deploy deploy-configmap deploy-gateway undeploy verify dry-run \
        status logs

KUBECTL ?= kubectl
NAMESPACE := gateway
TOOLS_NAMESPACE := tools

# Path to source config files (relative to POC root when run from this dir)
	OPA_DIR ?= ../../../config/opa
	TOOL_REGISTRY ?= ../../../config/tool-registry.yaml
	CAPABILITY_REGISTRY_V2 ?= ../../../config/capability-registry-v2.yaml
	MODEL_PROVIDER_CATALOG ?= ../../../config/model-provider-catalog.v2.yaml
	ATTESTATION_PUBLIC_KEY ?= ../../../config/attestation-ed25519.pub
	GUARD_ARTIFACT ?= ../../../config/guard-artifact.bin

help: ## Show this help message
	@echo "Gateway Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy (runs all steps in order)"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: deploy-configmap deploy-gateway ## Deploy all gateway components (ConfigMap, deployment, service)
	@echo ""
	@echo "Gateway deployment complete. Run 'make verify' to check health."

	deploy-configmap: ## Create/update ConfigMap from source OPA policies and tool registry
		@echo "=== Deploying Gateway ConfigMap ==="
		$(KUBECTL) apply -f gateway-namespace.yaml
		$(KUBECTL) apply -f gateway-rbac.yaml
		@echo "Creating ConfigMap from source policy files..."
		$(KUBECTL) -n $(NAMESPACE) create configmap gateway-config \
			--from-file=mcp_policy.rego=$(OPA_DIR)/mcp_policy.rego \
			--from-file=ui_policy.rego=$(OPA_DIR)/ui_policy.rego \
			--from-file=ui_csp_policy.rego=$(OPA_DIR)/ui_csp_policy.rego \
			--from-file=exfiltration.rego=$(OPA_DIR)/exfiltration.rego \
			--from-file=context_policy.rego=$(OPA_DIR)/context_policy.rego \
			--from-file=tool_grants.yaml=$(OPA_DIR)/tool_grants.yaml \
			--from-file=ui_capability_grants.yaml=$(OPA_DIR)/ui_capability_grants.yaml \
			--from-file=tool-registry.yaml=$(TOOL_REGISTRY) \
			--from-file=tool-registry.yaml.sig=$(TOOL_REGISTRY).sig \
			--from-file=capability-registry-v2.yaml=$(CAPABILITY_REGISTRY_V2) \
			--from-file=model-provider-catalog.v2.yaml=$(MODEL_PROVIDER_CATALOG) \
			--from-file=model-provider-catalog.v2.yaml.sig=$(MODEL_PROVIDER_CATALOG).sig \
			--from-file=attestation-ed25519.pub=$(ATTESTATION_PUBLIC_KEY) \
			--from-file=guard-artifact.bin=$(GUARD_ARTIFACT) \
			--from-file=guard-artifact.bin.sig=$(GUARD_ARTIFACT).sig \
			--dry-run=client -o yaml | $(KUBECTL) apply -f -
		@echo "ConfigMap created with OPA policies and tool registry."

deploy-gateway: ## Deploy gateway Deployment and Service
	@echo "=== Deploying PRECINCT Gateway ==="
	$(KUBECTL) apply -f gateway-deployment.yaml
	$(KUBECTL) apply -f gateway-service.yaml
	@echo "Waiting for gateway pod to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deployment/precinct-gateway --timeout=120s
	@echo "PRECINCT Gateway deployed."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify gateway health (pods, services, config)
	@echo "=== Gateway Pod Health ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=precinct-gateway
	@echo ""
	@echo "=== Gateway Service ==="
	$(KUBECTL) -n $(NAMESPACE) get svc precinct-gateway
	@echo ""
	@echo "=== ConfigMap Keys ==="
	$(KUBECTL) -n $(NAMESPACE) get configmap gateway-config -o jsonpath='{.data}' | \
		python3 -c "import sys,json; [print(f'  {k} ({len(v)} bytes)') for k,v in json.loads(sys.stdin.read()).items()]" 2>/dev/null || \
		$(KUBECTL) -n $(NAMESPACE) describe configmap gateway-config | head -30
	@echo ""
	@echo "=== Gateway Logs (last 10 lines) ==="
	$(KUBECTL) -n $(NAMESPACE) logs -l app.kubernetes.io/name=precinct-gateway --tail=10 2>/dev/null || echo "(no logs yet)"

status: ## Show pod and service status
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc
	@echo ""
	@echo "=== Deployments ==="
	$(KUBECTL) -n $(NAMESPACE) get deployments

logs: ## Tail gateway logs
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=precinct-gateway

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# Uses kubeconform if available (works offline), falls back to kubectl dry-run.
# Install kubeconform: brew install kubeconform
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			gateway-namespace.yaml \
			gateway-rbac.yaml \
			gateway-configmap.yaml \
			gateway-deployment.yaml \
			gateway-service.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in gateway-namespace.yaml gateway-rbac.yaml gateway-configmap.yaml \
			gateway-deployment.yaml gateway-service.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All gateway manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all gateway resources
	@echo "=== Removing PRECINCT Gateway ==="
	-$(KUBECTL) delete -f gateway-deployment.yaml --ignore-not-found
	-$(KUBECTL) delete -f gateway-service.yaml --ignore-not-found
	-$(KUBECTL) -n $(NAMESPACE) delete configmap gateway-config --ignore-not-found
	-$(KUBECTL) delete -f gateway-rbac.yaml --ignore-not-found
	@echo "Deleting namespace..."
	-$(KUBECTL) delete -f gateway-namespace.yaml --ignore-not-found
	@echo "Gateway removed."
