# ------------------------------------------------------------------------------
# NetworkPolicy Enforcement Verification - Makefile
# Story: RFA-9fv.8
#
# Targets for running NetworkPolicy verification tests against a live EKS cluster.
#
# Usage:
#   make test            # Run full verification suite (all 7 tests)
#   make test-positive   # Run connectivity tests (should succeed)
#   make test-negative   # Run isolation tests (should fail/timeout)
#   make deploy-test-pod # Deploy test pod into gateway namespace
#   make cleanup         # Remove all test pods from all namespaces
#   make validate        # Validate scripts and manifests offline (no cluster)
# ------------------------------------------------------------------------------

SHELL := /bin/bash
.DEFAULT_GOAL := test

SCRIPT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
VERIFY_SCRIPT := $(SCRIPT_DIR)/verify-network-policies.sh
VERIFY_POD := $(SCRIPT_DIR)/verify-pod.yaml
CI_SCRIPT := $(SCRIPT_DIR)/ci-network-policy-test.sh

# -- Live cluster tests --------------------------------------------------------

.PHONY: test
test: ## Run full NetworkPolicy verification suite (all 7 tests)
	@echo "Running full NetworkPolicy verification suite..."
	@$(VERIFY_SCRIPT)

.PHONY: test-positive
test-positive: ## Run connectivity tests (should succeed: gateway->mcp, gateway->otel, gateway DNS)
	@echo "Running positive (allow) tests..."
	@$(VERIFY_SCRIPT) --positive

.PHONY: test-negative
test-negative: ## Run isolation tests (should deny: mcp->gateway, mcp->internet, default->mcp, gateway->default)
	@echo "Running negative (deny) tests..."
	@$(VERIFY_SCRIPT) --negative

# -- Pod management ------------------------------------------------------------

.PHONY: deploy-test-pod
deploy-test-pod: ## Deploy test pod into gateway namespace (for manual testing)
	@echo "Deploying test pod into gateway namespace..."
	kubectl apply -f $(VERIFY_POD) -n gateway
	kubectl wait --for=condition=Ready pod/netpol-verify -n gateway --timeout=60s
	@echo "Test pod deployed. Use 'kubectl exec -n gateway netpol-verify -- <command>' to test."

.PHONY: deploy-test-pod-tools
deploy-test-pod-tools: ## Deploy test pod into tools namespace (for manual testing)
	@echo "Deploying test pod into tools namespace..."
	kubectl apply -f $(VERIFY_POD) -n tools
	kubectl wait --for=condition=Ready pod/netpol-verify -n tools --timeout=60s
	@echo "Test pod deployed. Use 'kubectl exec -n tools netpol-verify -- <command>' to test."

.PHONY: cleanup
cleanup: ## Remove all test pods from all namespaces
	@$(VERIFY_SCRIPT) --cleanup

# -- Offline validation --------------------------------------------------------

.PHONY: validate
validate: validate-scripts validate-manifests ## Validate scripts and manifests offline (no cluster needed)
	@echo "All offline validations passed."

.PHONY: validate-scripts
validate-scripts: ## Validate shell script syntax
	@echo "Validating shell script syntax..."
	bash -n $(VERIFY_SCRIPT)
	@echo "  verify-network-policies.sh: OK"
	@if [ -f "$(CI_SCRIPT)" ]; then \
		bash -n $(CI_SCRIPT); \
		echo "  ci-network-policy-test.sh: OK"; \
	fi

.PHONY: validate-manifests
validate-manifests: ## Validate Kubernetes manifests with kubeconform
	@echo "Validating Kubernetes manifests..."
	@if command -v kubeconform &>/dev/null; then \
		kubeconform -strict -summary $(VERIFY_POD); \
	else \
		echo "  kubeconform not available, using kubectl dry-run"; \
		kubectl apply --dry-run=client -f $(VERIFY_POD) 2>/dev/null && echo "  verify-pod.yaml: OK" || echo "  verify-pod.yaml: INVALID"; \
	fi

# -- Help ----------------------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@echo "NetworkPolicy Verification Targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-22s %s\n", $$1, $$2}'
