# ------------------------------------------------------------------------------
# SPIRE Deployment Makefile
# Story: RFA-9fv.3
#
# Targets for deploying and managing SPIRE on EKS.
# Deployment order: namespace/RBAC -> server -> agent -> registration entries
# ------------------------------------------------------------------------------
.PHONY: help deploy deploy-server deploy-agent deploy-entries undeploy verify \
        dry-run status logs-server logs-agent

KUBECTL ?= kubectl
NAMESPACE := spire-system

help: ## Show this help message
	@echo "SPIRE Deployment -- EKS Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Deployment order: make deploy-server && make deploy-agent && make deploy-entries"

# ---------------------------------------------------------------------------
# Deployment targets
# ---------------------------------------------------------------------------

deploy: deploy-server deploy-agent deploy-entries ## Deploy all SPIRE components (server, agent, entries)
	@echo ""
	@echo "SPIRE deployment complete. Run 'make verify' to check health."

deploy-server: ## Deploy SPIRE Server (namespace, RBAC, StatefulSet, services)
	@echo "=== Deploying SPIRE Server ==="
	$(KUBECTL) apply -f namespace.yaml
	$(KUBECTL) apply -f bundle-configmap.yaml
	$(KUBECTL) apply -f server-rbac.yaml
	$(KUBECTL) apply -f server-configmap.yaml
	$(KUBECTL) apply -f server-service.yaml
	$(KUBECTL) apply -f server-statefulset.yaml
	@echo "Waiting for SPIRE Server pods to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status statefulset/spire-server --timeout=120s
	@echo "SPIRE Server deployed."

deploy-agent: ## Deploy SPIRE Agent (RBAC, DaemonSet)
	@echo "=== Deploying SPIRE Agent ==="
	$(KUBECTL) apply -f agent-rbac.yaml
	$(KUBECTL) apply -f agent-configmap.yaml
	$(KUBECTL) apply -f agent-daemonset.yaml
	@echo "Waiting for SPIRE Agent pods to be ready..."
	$(KUBECTL) -n $(NAMESPACE) rollout status daemonset/spire-agent --timeout=120s
	@echo "SPIRE Agent deployed."

deploy-entries: ## Register workload entries (gateway, tools, spike)
	@echo "=== Registering SPIRE entries ==="
	@echo "Using kubectl exec to run registration inside the server pod..."
	$(KUBECTL) -n $(NAMESPACE) cp registration-entries.yaml spire-server-0:/tmp/register-script.yaml 2>/dev/null || true
	$(KUBECTL) -n $(NAMESPACE) create configmap spire-registration-script \
		--from-file=register.sh=registration-entries.yaml \
		--dry-run=client -o yaml | $(KUBECTL) apply -f - 2>/dev/null || true
	@echo "Running registration script in server pod..."
	$(KUBECTL) -n $(NAMESPACE) exec spire-server-0 -- sh -c '\
		SOCK="/tmp/spire-server/private/api.sock" && \
		/opt/spire/bin/spire-server entry create -socketPath $$SOCK -node \
			-spiffeID spiffe://precinct.poc/agent/k8s-psat \
			-selector k8s_psat:cluster:precinct-poc \
			-selector k8s_psat:agent_ns:spire-system \
			-selector k8s_psat:agent_sa:spire-agent 2>/dev/null || true && \
		/opt/spire/bin/spire-server entry create -socketPath $$SOCK \
			-parentID spiffe://precinct.poc/agent/k8s-psat \
			-spiffeID spiffe://precinct.poc/ns/gateway/sa/mcp-security-gateway \
			-selector k8s:ns:gateway -selector k8s:sa:mcp-security-gateway \
			-dns mcp-security-gateway \
			-dns mcp-security-gateway.gateway.svc.cluster.local 2>/dev/null || true && \
		/opt/spire/bin/spire-server entry create -socketPath $$SOCK \
			-parentID spiffe://precinct.poc/agent/k8s-psat \
			-spiffeID spiffe://precinct.poc/ns/tools/sa/mcp-tool \
			-selector k8s:ns:tools -selector k8s:sa:mcp-tool 2>/dev/null || true && \
		/opt/spire/bin/spire-server entry create -socketPath $$SOCK \
			-parentID spiffe://precinct.poc/agent/k8s-psat \
			-spiffeID spiffe://precinct.poc/ns/spike-system/sa/spike-nexus \
			-selector k8s:ns:spike-system -selector k8s:sa:spike-nexus \
			-dns spike-nexus \
			-dns spike-nexus.spike-system.svc.cluster.local 2>/dev/null || true && \
		echo "" && echo "=== Current entries ===" && \
		/opt/spire/bin/spire-server entry show -socketPath $$SOCK'
	@echo ""
	@echo "Registration complete."

# ---------------------------------------------------------------------------
# Verification targets
# ---------------------------------------------------------------------------

verify: ## Verify SPIRE health (server, agent, entries)
	@echo "=== SPIRE Server Health ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=spire-server
	@echo ""
	@echo "=== SPIRE Agent Health ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -l app.kubernetes.io/name=spire-agent -o wide
	@echo ""
	@echo "=== Server Healthcheck ==="
	$(KUBECTL) -n $(NAMESPACE) exec spire-server-0 -- \
		/opt/spire/bin/spire-server healthcheck \
		-socketPath /tmp/spire-server/private/api.sock || echo "FAILED"
	@echo ""
	@echo "=== Registration Entries ==="
	$(KUBECTL) -n $(NAMESPACE) exec spire-server-0 -- \
		/opt/spire/bin/spire-server entry show \
		-socketPath /tmp/spire-server/private/api.sock || echo "No entries"

status: ## Show pod status for all SPIRE components
	@echo "=== Pods ==="
	$(KUBECTL) -n $(NAMESPACE) get pods -o wide
	@echo ""
	@echo "=== Services ==="
	$(KUBECTL) -n $(NAMESPACE) get svc
	@echo ""
	@echo "=== StatefulSets ==="
	$(KUBECTL) -n $(NAMESPACE) get statefulsets
	@echo ""
	@echo "=== DaemonSets ==="
	$(KUBECTL) -n $(NAMESPACE) get daemonsets

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

logs-server: ## Tail SPIRE Server logs (pod 0)
	$(KUBECTL) -n $(NAMESPACE) logs -f spire-server-0

logs-agent: ## Tail SPIRE Agent logs (first pod)
	$(KUBECTL) -n $(NAMESPACE) logs -f -l app.kubernetes.io/name=spire-agent --max-log-requests=1

# ---------------------------------------------------------------------------
# Dry run (validation without a cluster)
# Uses kubeconform if available (works offline), falls back to kubectl dry-run.
# Install kubeconform: brew install kubeconform
# ---------------------------------------------------------------------------

dry-run: ## Validate all manifests (kubeconform or kubectl dry-run)
	@if command -v kubeconform >/dev/null 2>&1; then \
		echo "=== Validating with kubeconform (offline) ==="; \
		kubeconform -summary -strict \
			namespace.yaml bundle-configmap.yaml \
			server-rbac.yaml server-configmap.yaml \
			server-service.yaml server-statefulset.yaml \
			registration-entries.yaml \
			agent-rbac.yaml agent-configmap.yaml \
			agent-daemonset.yaml; \
	else \
		echo "=== Validating with kubectl dry-run (requires cluster) ==="; \
		for f in namespace.yaml bundle-configmap.yaml server-rbac.yaml \
			server-configmap.yaml server-service.yaml server-statefulset.yaml \
			registration-entries.yaml agent-rbac.yaml agent-configmap.yaml \
			agent-daemonset.yaml; do \
			$(KUBECTL) apply --dry-run=client -f "$$f"; \
		done; \
	fi
	@echo "All SPIRE manifests valid."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

undeploy: ## Remove all SPIRE resources
	@echo "=== Removing SPIRE ==="
	-$(KUBECTL) delete -f agent-daemonset.yaml --ignore-not-found
	-$(KUBECTL) delete -f agent-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f agent-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f registration-entries.yaml --ignore-not-found
	-$(KUBECTL) delete -f server-statefulset.yaml --ignore-not-found
	-$(KUBECTL) delete -f server-service.yaml --ignore-not-found
	-$(KUBECTL) delete -f server-configmap.yaml --ignore-not-found
	-$(KUBECTL) delete -f server-rbac.yaml --ignore-not-found
	-$(KUBECTL) delete -f bundle-configmap.yaml --ignore-not-found
	@echo "Deleting PVCs..."
	-$(KUBECTL) -n $(NAMESPACE) delete pvc -l app.kubernetes.io/name=spire-server --ignore-not-found
	@echo "Deleting namespace..."
	-$(KUBECTL) delete -f namespace.yaml --ignore-not-found
	@echo "SPIRE removed."
