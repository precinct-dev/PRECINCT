# ===========================================================================
# 1. Variables and helpers
# ===========================================================================

# Container image config
REGISTRY ?= ghcr.io
IMAGE_PREFIX ?= $(REGISTRY)/$(shell git config --get remote.origin.url 2>/dev/null | sed 's|.*github.com[:/]\(.*\)\.git|\1|' | tr '[:upper:]' '[:lower:]')/precinct
GATEWAY_IMAGE ?= $(IMAGE_PREFIX)/mcp-security-gateway
S3_MCP_IMAGE ?= $(IMAGE_PREFIX)/s3-mcp-server
IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Local registry (CNCF Distribution) for Docker Desktop K8s
LOCAL_REGISTRY ?= localhost:5050
K8S_REGISTRY ?= registry:5000

# Docker Compose
COMPOSE_DIR := deploy/compose
DC := docker compose -f $(COMPOSE_DIR)/docker-compose.yml

# Compliance tooling
AUDIT_LOG ?= /tmp/audit.jsonl
COMPLIANCE_VENV := tools/compliance/.venv
COMPLIANCE_PYTHON := $(COMPLIANCE_VENV)/bin/python3
CONFORMANCE_REPORT ?= build/conformance/conformance-report.json

# Validation suite filter (compose|k8s, default: all)
SUITE ?=

# run_demo_test -- Run a test script and report PASS/FAIL
# Usage: $(call run_demo_test,<label>,<script>)
define run_demo_test
	@if bash $(2); then echo "$(1): PASS"; else echo "$(1): FAIL"; exit 1; fi
endef

# ===========================================================================
# Default
# ===========================================================================

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-35s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ===========================================================================
# 2. Core lifecycle (up, down, clean, repave, upgrade, logs)
# ===========================================================================

.PHONY: up down clean repave upgrade-check upgrade upgrade-all logs
.PHONY: compose-verify compose-bootstrap-verify

up: compose-verify ## Start Docker Compose stack (waits for all services healthy)
	@if [ ! -f .env ]; then \
		echo "Creating .env from .env.example (set GROQ_API_KEY for deep scan)..."; \
		cp .env.example .env; \
	fi
	@if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then \
		echo "phoenix-observability-network not found; starting Phoenix stack..."; \
		$(MAKE) phoenix-up; \
	fi
	@echo "Building and starting services (waiting for all health checks)..."
	@if $(DC) up -d --build --wait --wait-timeout 180; then \
		echo "All services healthy."; \
	else \
		echo "WARN: docker compose --wait timed out. Checking core service readiness..."; \
		if ! bash scripts/compose-health-check.sh --verbose; then \
			echo "Attempting gateway-only recovery after compose dependency timeout..."; \
			$(DC) up -d --no-deps mcp-security-gateway >/dev/null 2>&1 || true; \
		fi; \
		echo "Waiting up to 60s for core services to become healthy..."; \
		ready=0; \
		for _ in $$(seq 1 12); do \
			if bash scripts/compose-health-check.sh; then \
				ready=1; \
				break; \
			fi; \
			sleep 5; \
		done; \
		if [ "$$ready" -ne 1 ]; then \
			echo "ERROR: Compose startup failed and required services are not ready."; \
			bash scripts/compose-health-check.sh --verbose || true; \
			$(DC) ps; \
			exit 1; \
		fi; \
		echo "Core services are ready despite compose wait timeout; continuing."; \
	fi
	@$(MAKE) compose-bootstrap-verify
	@echo "Running register-spire for any additional entries..."
	$(MAKE) register-spire

down: ## Stop Docker Compose stack
	$(DC) down

clean: ## Full cleanup (containers, volumes, build artifacts, logs, SPIRE state)
	$(DC) down -v
	-docker compose -f $(COMPOSE_DIR)/docker-compose.phoenix.yml down -v >/dev/null 2>&1 || true
	-docker compose -f $(COMPOSE_DIR)/docker-compose.opensearch.yml down -v >/dev/null 2>&1 || true
	rm -rf build/sbom/ build/bin/
	@echo "Clearing SPIRE data directories (stale SVIDs prevent clean restart)..."
	rm -rf data/spire-server/ data/spire-agent/
	@if [ -d build/logs ]; then rm -rf build/logs/*; fi
	$(MAKE) -C cli clean

repave: ## Repave containers (COMPONENT=<name> for single, default: all)
	@if [ -n "$(COMPONENT)" ]; then \
		bash scripts/repave.sh "$(COMPONENT)"; \
	else \
		bash scripts/repave.sh --all; \
	fi

upgrade-check: ## Show current vs latest versions (containers, Go modules, Python deps)
	@bash scripts/upgrade-check.sh --format table
	@echo ""
	@bash scripts/upgrade-check.sh --format json

upgrade: ## Upgrade a single component (COMPONENT=<name> VERIFY=1)
	@if [ -z "$(COMPONENT)" ]; then \
		echo "ERROR: COMPONENT is required (ex: make upgrade COMPONENT=keydb)"; \
		exit 1; \
	fi
	@args="--component $(COMPONENT)"; \
	if [ "$(VERIFY)" = "1" ]; then args="$$args --verify"; fi; \
	bash scripts/upgrade.sh $$args

upgrade-all: ## Upgrade all non-pinned components (VERIFY=1)
	@args="--all"; \
	if [ "$(VERIFY)" = "1" ]; then args="$$args --verify"; fi; \
	bash scripts/upgrade.sh $$args

logs: ## Tail gateway logs
	$(DC) logs -f mcp-security-gateway

# Hidden: compose verification helpers (called by up)
compose-verify:
	@bash scripts/compose-verify.sh

compose-bootstrap-verify:
	@bash scripts/compose-bootstrap-verify.sh

# ===========================================================================
# 3. Phoenix
# ===========================================================================

.PHONY: phoenix-up phoenix-down phoenix-reset

phoenix-up: ## Start standalone Phoenix + OTel collector (persistent traces)
	docker compose -f $(COMPOSE_DIR)/docker-compose.phoenix.yml up -d --build --wait --wait-timeout 60
	@echo "Phoenix UI: http://localhost:6006"

phoenix-down: ## Stop Phoenix stack (preserves trace data)
	docker compose -f $(COMPOSE_DIR)/docker-compose.phoenix.yml down

phoenix-reset: ## Stop Phoenix stack and destroy trace data
	docker compose -f $(COMPOSE_DIR)/docker-compose.phoenix.yml down -v

# ===========================================================================
# 4. OpenSearch Observability (optional)
# ===========================================================================

.PHONY: opensearch-up opensearch-down opensearch-reset opensearch-seed opensearch-validate
.PHONY: observability-up observability-down observability-reset

opensearch-up: ## Start OpenSearch + Dashboards + audit forwarder (optional compliance/forensics profile)
	@echo "Reconfiguring gateway audit sink for OpenSearch profile..."
	$(DC) -f $(COMPOSE_DIR)/docker-compose.opensearch-bridge.yml up -d --no-deps mcp-security-gateway
	@echo "Starting OpenSearch stack..."
	docker compose -f $(COMPOSE_DIR)/docker-compose.opensearch.yml up -d --wait --wait-timeout 120
	@echo "OpenSearch API: http://localhost:9200"
	@echo "OpenSearch Dashboards: http://localhost:5601"
	@echo "Next: make opensearch-seed"

opensearch-down: ## Stop OpenSearch + Dashboards stack (preserves OpenSearch data)
	docker compose -f $(COMPOSE_DIR)/docker-compose.opensearch.yml down

opensearch-reset: ## Stop OpenSearch + Dashboards and destroy all OpenSearch data
	docker compose -f $(COMPOSE_DIR)/docker-compose.opensearch.yml down -v

opensearch-seed: ## Seed OpenSearch index template and import PRECINCT dashboard objects
	@bash scripts/observability/seed-opensearch-dashboards.sh

opensearch-validate: ## Validate OpenSearch health, template, and dashboard API
	@bash scripts/observability/validate-opensearch-stack.sh

observability-up: phoenix-up opensearch-up ## Start both observability backends (Phoenix + OpenSearch)

observability-down: ## Stop both observability backends (preserves data)
	$(MAKE) phoenix-down
	$(MAKE) opensearch-down

observability-reset: ## Destroy all observability backend data (Phoenix + OpenSearch)
	$(MAKE) phoenix-reset
	$(MAKE) opensearch-reset

# ===========================================================================
# 5. CI / Quality (ci, lint, test, production-readiness-validate)
# ===========================================================================

.PHONY: ci lint test test-unit test-integration test-opa test-cli test-e2e production-readiness-validate story-evidence-validate tracker-surface-validate

ci: lint test conformance build-images ## Full CI pipeline (lint + test + conformance + build)
	@echo "CI pipeline complete"

lint: ## Run linters
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		go fmt ./...; \
		go vet ./...; \
	fi

test: test-unit test-integration test-opa test-cli ## Run all tests (unit + tagged integration + OPA + CLI)
	@echo "Test suite complete"

test-unit: ## Run unit tests (Go packages and non-tagged suites)
	@echo "Running unit tests..."
	go test ./internal/gateway/... -v -cover
	go test ./internal/gateway/middleware/... -v -cover
	go test ./tests/unit/... -v

test-integration: ## Run tagged integration tests against an ensured local stack
	@echo "Ensuring local stack is healthy for tagged integration tests..."
	@bash scripts/ensure-stack.sh --resilient
	@echo ""
	@echo "Running tagged integration tests..."
	@keydb_url="$$(bash scripts/resolve-keydb-url.sh)"; \
	echo "Using PRECINCT_KEYDB_URL=$$keydb_url"; \
	PRECINCT_KEYDB_URL="$$keydb_url" go test -tags=integration ./tests/integration/... -v -timeout 30m

test-opa: ## Run OPA policy tests
	@echo "Running OPA policy tests..."
	@if command -v opa >/dev/null 2>&1; then \
		opa test config/opa/ -v; \
	else \
		echo "WARNING: opa not installed, skipping OPA tests"; \
	fi

test-cli: ## Run CLI tests (delegates to cli/Makefile)
	$(MAKE) -C cli test

test-e2e: demo ## Run the full E2E demo suite (Compose + K8s)

production-readiness-validate: security-scan-strict security-scan-validate manifest-policy-check control-matrix-check ## Strict production-readiness security evidence gate
	@echo "production-readiness-validate: PASS"

story-evidence-validate: ## Validate evidence paths in an nd story (STORY_ID=<id>)
	@if [ -z "$(STORY_ID)" ]; then \
		echo "ERROR: STORY_ID is required (ex: make story-evidence-validate STORY_ID=RFA-565d)"; \
		exit 1; \
	fi
	tests/e2e/validate_story_evidence_paths.sh "$(STORY_ID)"

tracker-surface-validate: ## Audit active release workflow surfaces for stale tracker references
	@bash -eu -o pipefail -c ' \
		files=( \
			"AGENTS.md" \
			"README.md" \
			"Makefile" \
			"docs/current-state-and-roadmap.md" \
			"docs/deployment-guide.md" \
			"docs/security/evidence-collection.md" \
			"docs/operations/runbooks/incident-triage-and-response.md" \
			"docs/operations/runbooks/rollback-runbook.md" \
			"docs/operations/runbooks/security-event-response.md" \
			"tests/e2e/validate_story_evidence_paths.sh" \
			"tests/e2e/validate_readiness_state_integrity.sh" \
		); \
		found=0; \
		for rel in "$${files[@]}"; do \
			abs="$(CURDIR)/$$rel"; \
			while IFS= read -r match; do \
				[[ -n "$$match" ]] || continue; \
				line_text="$${match#*:}"; \
				lower=$$(printf "%s" "$$line_text" | tr "[:upper:]" "[:lower:]"); \
				case "$$lower" in \
					*historical*|*archiv*|*legacy*|*compatibility*|*"does not require"*|*"canonical tracker"*|*"rg -n"*) \
						continue \
						;; \
				esac; \
				echo "[STALE] $$match"; \
				found=1; \
			done < <(rg -n "\\bbd\\b|beads" "$$abs" || true); \
		done; \
		if [[ "$$found" -ne 0 ]]; then \
			echo "[FAIL] found non-archival bd/beads references in active release workflow surfaces" >&2; \
			exit 1; \
		fi; \
		echo "[PASS] release workflow surfaces use nd as the active tracker; remaining beads references are archival only" \
	'

# ===========================================================================
# 5. Demos (demo, demo-compose, demo-k8s, demo-cli)
# ===========================================================================

.PHONY: demo demo-compose demo-k8s demo-cli compose-down

demo: ## Run E2E demo (Docker Compose + K8s)
	@bash examples/run.sh compose
	@bash examples/run.sh k8s

demo-compose: ## Run E2E demo (Docker Compose; leaves stack running for inspection)
	@bash examples/run.sh compose --no-teardown

demo-k8s: ## Run E2E demo (K8s; leaves cluster running for inspection)
	@bash examples/run.sh k8s --no-teardown

compose-down: ## Tear down Docker Compose stack and volumes
	$(DC) down -v

demo-cli: ## Run all CLI demos (precinct CLI, operate, compliance, repave, upgrade)
	@bash scripts/ensure-stack.sh --resilient
	@mkdir -p build/bin
	@go build -o build/bin/precinct ./cli/agw/
	$(call run_demo_test,precinct-cli,tests/e2e/test_agw_cli.sh)
	$(call run_demo_test,precinct-operate,tests/e2e/test_agw_operate.sh)
	$(call run_demo_test,precinct-compliance,tests/e2e/test_agw_compliance.sh)
	$(call run_demo_test,repave,tests/e2e/test_repave.sh)
	$(call run_demo_test,upgrade,tests/e2e/test_upgrade.sh)

# ===========================================================================
# 6. Kubernetes (k8s-up, k8s-down, k8s-validate)
# ===========================================================================

.PHONY: k8s-up k8s-down k8s-validate k8s-opensearch-up k8s-opensearch-down k8s-sync-config k8s-check-config

k8s-sync-config: ## Sync K8s overlay gateway config from canonical config/ source
	@bash scripts/k8s-sync-gateway-config.sh --sync

k8s-check-config: ## Check K8s overlay gateway config for drift (CI use)
	@bash scripts/k8s-sync-gateway-config.sh --check

k8s-up: ## Deploy to local K8s (Docker Desktop)
	@if ! kubectl cluster-info 2>/dev/null | grep -q 'Kubernetes control plane'; then \
		echo "ERROR: No Kubernetes cluster. Enable in Docker Desktop: Settings -> Kubernetes"; \
		exit 1; \
	fi
	@echo "Syncing K8s gateway config from canonical source..."
	@bash scripts/k8s-sync-gateway-config.sh --sync
	$(MAKE) k8s-registry
	@echo "Building and pushing local images..."
	docker build -f deploy/compose/Dockerfile.gateway -t mcp-security-gateway:latest .
	docker build -f examples/mock-mcp-server/Dockerfile -t poc-mock-mcp-server:latest examples/mock-mcp-server/
	docker build -f deploy/compose/Dockerfile.spire-agent -t spire-agent-wrapper:latest .
	docker tag mcp-security-gateway:latest $(LOCAL_REGISTRY)/mcp-security-gateway:latest
	docker push $(LOCAL_REGISTRY)/mcp-security-gateway:latest
	docker tag poc-mock-mcp-server:latest $(LOCAL_REGISTRY)/poc-mock-mcp-server:latest
	docker push $(LOCAL_REGISTRY)/poc-mock-mcp-server:latest
	docker tag spire-agent-wrapper:latest $(LOCAL_REGISTRY)/spire-agent-wrapper:latest
	docker push $(LOCAL_REGISTRY)/spire-agent-wrapper:latest
	docker build -f deploy/compose/Dockerfile.spike-keeper -t spike-keeper:latest .
	docker tag spike-keeper:latest $(LOCAL_REGISTRY)/spike-keeper:latest
	docker push $(LOCAL_REGISTRY)/spike-keeper:latest
	docker build -f examples/content-scanner/Dockerfile -t poc-content-scanner:latest examples/content-scanner/
	docker tag poc-content-scanner:latest $(LOCAL_REGISTRY)/poc-content-scanner:latest
	docker push $(LOCAL_REGISTRY)/poc-content-scanner:latest
	$(MAKE) k8s-prereqs
	@echo "Cleaning up completed SPIKE jobs for re-apply..."
	-kubectl -n spike-system delete job spike-bootstrap --ignore-not-found 2>/dev/null
	-kubectl -n spike-system delete job spike-secret-seeder --ignore-not-found 2>/dev/null
	@echo "Applying overlay (pass 1: base resources + ConstraintTemplates)..."
	@-bash scripts/k8s-apply-local-overlay-pass1.sh
	@echo "Waiting for Gatekeeper to process ConstraintTemplates..."
	@sleep 10
	@echo "Applying overlay (pass 2: constraints, policies)..."
	@-kubectl apply -k infra/eks/overlays/local/ 2>&1
	@echo "Generating TLS certs for policy-controller webhook..."
	@bash scripts/k8s-generate-webhook-tls.sh
	@echo "Waiting for SPIRE infrastructure..."
	-kubectl -n spire-system rollout status statefulset/spire-server --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIRE Server not yet ready"
	-kubectl -n spire-system rollout status daemonset/spire-agent --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIRE Agent not yet ready"
	@echo "Registering SPIRE workload entries..."
	$(MAKE) k8s-register-spire
	@echo "Waiting for SPIKE Keeper..."
	-kubectl -n spike-system rollout status deployment/spike-keeper --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIKE Keeper not yet ready"
	@echo "Waiting for SPIKE Nexus (SQLite mode)..."
	-kubectl -n spike-system rollout status deployment/spike-nexus --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIKE Nexus not yet ready"
	@echo "Checking SPIKE Nexus service endpoint readiness..."
	@{ \
		ready_ip=""; \
		for i in $$(seq 1 60); do \
			ready_ip="$$(kubectl -n spike-system get endpoints spike-nexus -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true)"; \
			if [ -n "$$ready_ip" ]; then \
				break; \
			fi; \
			sleep 2; \
		done; \
		if [ -z "$$ready_ip" ]; then \
			echo "WARNING: SPIKE Nexus endpoint not ready yet; bootstrap job may retry until Nexus is available"; \
		fi; \
	}
	@echo "Applying SPIKE Bootstrap job (after SPIRE registration)..."
	-kubectl -n spike-system apply -f infra/eks/overlays/local/spike-bootstrap-job.yaml >/dev/null 2>&1 || true
	@echo "Waiting for SPIKE Bootstrap job..."
	-kubectl -n spike-system wait --for=condition=complete job/spike-bootstrap --timeout=240s 2>/dev/null || \
		echo "WARNING: SPIKE Bootstrap not yet complete"
	@echo "Applying SPIKE Secret Seeder job (after bootstrap)..."
	-kubectl -n spike-system apply -f infra/eks/spike/seeder-job.yaml >/dev/null 2>&1 || true
	@echo "Waiting for SPIKE Secret Seeder job..."
	-kubectl -n spike-system wait --for=condition=complete job/spike-secret-seeder --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIKE Secret Seeder not yet complete"
	@echo "Waiting for remaining pods..."
	-kubectl -n data rollout status deployment/keydb --timeout=60s 2>/dev/null || \
		echo "WARNING: KeyDB not yet ready"
	-kubectl -n tools rollout status deployment/mcp-server --timeout=60s 2>/dev/null || \
		echo "WARNING: MCP Server not yet ready"
	-kubectl -n gateway rollout status deployment/mcp-security-gateway --timeout=120s 2>/dev/null || \
		echo "WARNING: Gateway not yet ready"
	-kubectl -n cosign-system rollout status deployment/policy-controller-webhook --timeout=60s 2>/dev/null || \
		echo "WARNING: policy-controller webhook not yet ready"
	@echo ""
	@echo "Gateway: http://localhost:30090"
	@echo "Health:  curl -s http://localhost:30090/health"
	@echo ""
	@echo "To enable deep scan (optional):"
	@echo "  kubectl -n gateway create secret generic gateway-secrets --from-literal=groq-api-key=$$GROQ_API_KEY --dry-run=client -o yaml | kubectl apply -f -"
	@echo "  kubectl -n gateway rollout restart deploy/mcp-security-gateway"

k8s-down: ## Tear down local K8s deployment
	@-kubectl delete -k infra/eks/overlays/local/ --ignore-not-found 2>&1 | grep -v -E 'ensure CRDs are installed first|resource mapping not found'
	@echo "Cleaning up Gatekeeper cluster-scoped resources..."
	-kubectl delete validatingwebhookconfigurations gatekeeper-validating-webhook-configuration --ignore-not-found 2>/dev/null
	-kubectl delete mutatingwebhookconfigurations gatekeeper-mutating-webhook-configuration --ignore-not-found 2>/dev/null
	-kubectl -n spire-system delete pvc -l app.kubernetes.io/name=spire-server --ignore-not-found 2>/dev/null

k8s-opensearch-up: k8s-up ## Deploy local K8s stack plus optional OpenSearch observability extension
	@echo "Applying OpenSearch extension overlay..."
	@-kubectl apply -k infra/eks/overlays/local-opensearch/ 2>&1
	-kubectl -n observability rollout status statefulset/opensearch --timeout=180s 2>/dev/null || \
		echo "WARNING: OpenSearch not yet ready"
	-kubectl -n observability rollout status deployment/opensearch-dashboards --timeout=180s 2>/dev/null || \
		echo "WARNING: OpenSearch Dashboards not yet ready"
	-kubectl -n observability rollout status daemonset/opensearch-audit-forwarder --timeout=180s 2>/dev/null || \
		echo "WARNING: OpenSearch audit forwarder not yet ready"

k8s-opensearch-down: ## Remove only OpenSearch extension resources from local K8s deployment
	@-kubectl delete -k infra/eks/observability/opensearch --ignore-not-found 2>&1 | grep -v -E 'ensure CRDs are installed first|resource mapping not found'

k8s-validate: ## Validate K8s overlays and Phase 3 gateway wiring (offline-first)
	@echo "Checking K8s gateway config for drift..."
	@bash scripts/k8s-sync-gateway-config.sh --check
	@set -e; \
	overlays="local local-opensearch dev staging prod"; \
	for o in $$overlays; do \
		echo "Building overlay: $$o"; \
		kustomize build "infra/eks/overlays/$$o" >"/tmp/precinct-k8s-$$o.yaml"; \
	done; \
	if command -v kubeconform >/dev/null 2>&1; then \
		for o in $$overlays; do \
			echo "Schema validation (kubeconform): $$o"; \
			kubeconform -summary -strict -ignore-missing-schemas "/tmp/precinct-k8s-$$o.yaml"; \
		done; \
	else \
		echo "WARNING: kubeconform not installed, skipping schema validation"; \
	fi; \
	echo "Validating Phase 3 capability registry wiring..."; \
	for o in $$overlays; do \
		file="/tmp/precinct-k8s-$$o.yaml"; \
		grep -q 'CAPABILITY_REGISTRY_V2_PATH' "$$file" || { echo "Missing CAPABILITY_REGISTRY_V2_PATH in $$o overlay"; exit 1; }; \
		grep -q 'capability-registry-v2.yaml' "$$file" || { echo "Missing capability-registry-v2.yaml mount/data in $$o overlay"; exit 1; }; \
	done; \
	echo "Validating non-local gateway prod transport wiring..."; \
	for o in dev staging prod; do \
		file="/tmp/precinct-k8s-$$o.yaml"; \
		awk ' \
			BEGIN { RS="---"; dep=""; svc="" } \
			$$0 ~ /kind:[[:space:]]*Deployment([[:space:]]|$$)/ && $$0 ~ /name:[[:space:]]*mcp-security-gateway([[:space:]]|$$)/ { dep=$$0 } \
			$$0 ~ /kind:[[:space:]]*Service([[:space:]]|$$)/ && $$0 ~ /name:[[:space:]]*mcp-security-gateway([[:space:]]|$$)/ { svc=$$0 } \
			END { \
				ok=1; \
				if (dep == "" || svc == "") ok=0; \
				if (dep !~ /name:[[:space:]]*SPIFFE_MODE/ || dep !~ /value:[[:space:]]*"?prod"?/) ok=0; \
				if (dep !~ /name:[[:space:]]*SPIFFE_ENDPOINT_SOCKET/ || dep !~ /run\/spire\/sockets\/agent\.sock/) ok=0; \
				if (dep !~ /name:[[:space:]]*SPIFFE_LISTEN_PORT/ || dep !~ /value:[[:space:]]*"?9090"?/) ok=0; \
				if (dep !~ /containerPort:[[:space:]]*9090/) ok=0; \
				if (dep !~ /livenessProbe:/ || dep !~ /readinessProbe:/ || dep !~ /- \/app\/gateway/ || dep !~ /- health/) ok=0; \
				if (svc !~ /port:[[:space:]]*9090/ || svc !~ /targetPort:[[:space:]]*http/) ok=0; \
				exit(ok ? 0 : 1); \
			} \
		' "$$file" || { echo "Gateway prod transport wiring check failed for $$o overlay"; exit 1; }; \
	done; \
	echo "Validating admission wiring (namespace scope, include labels, keyless identity bounds)..."; \
	tests/e2e/admission/verify-admission-manifest-wiring.sh; \
	echo "Validating staging/prod overlay image digests against Gatekeeper semantics..."; \
	bash tests/e2e/admission/verify-overlay-image-digests.sh; \
	echo "Validating network policy hardening wiring..."; \
	tests/e2e/network-policy/verify-network-policy-manifest-wiring.sh; \
	echo "Validating local K8s demo identity wiring..."; \
	tests/e2e/validate_local_demo_identity_wiring.sh; \
	echo "Validating strict runtime wiring (K8s + Compose)..."; \
	tests/e2e/validate_strict_runtime_wiring.sh; \
	echo "Validating strict overlay operationalization (no placeholders/literal runtime secrets)..."; \
	tests/e2e/validate_strict_overlay_operationalization.sh; \
	echo "k8s-validate: PASS"

# ===========================================================================
# 7. Validation (validate, story-evidence-validate)
# ===========================================================================

.PHONY: validate validate-compose validate-k8s

validate: ## Run all offline validation suites (SUITE=compose|k8s to filter)
	@if [ -z "$(SUITE)" ] || [ "$(SUITE)" = "compose" ]; then \
		$(MAKE) validate-compose; \
	fi
	@if [ -z "$(SUITE)" ] || [ "$(SUITE)" = "k8s" ]; then \
		$(MAKE) validate-k8s; \
	fi
	@echo "validate: PASS"

# ===========================================================================
# --- Hidden targets (callable by name, not in make help) ---
# ===========================================================================

# ---------------------------------------------------------------------------
# 8. Individual validates (validate-compose, validate-k8s, individual scripts)
# ---------------------------------------------------------------------------

validate-compose:
	@echo "=== Compose / doc validation suite ==="
	@bash scripts/compose-verify.sh
	@bash scripts/compose-production-intent-preflight.sh
	@bash tests/e2e/validate_compose_signature_prereqs.sh
	@bash tests/e2e/validate_compose_production_intent_supply_chain.sh
	@bash tests/e2e/validate_compose_production_intent_egress.sh
	@bash tests/e2e/validate_framework_taxonomy_mappings.sh
	@bash tests/e2e/validate_app_integration_pack_model.sh
	@bash tests/e2e/validate_app_integration_strategy_docs.sh
	@bash tests/e2e/validate_observability_evidence_gate.sh
	@bash tests/e2e/validate_gateway_bypass_case26.sh
	@bash tests/e2e/validate_managed_cloud_bootstrap_prereqs.sh
	@bash tests/e2e/validate_operational_readiness_pack.sh
	@bash tests/e2e/validate_immutable_audit_sink.sh
	@bash ports/openclaw/tests/e2e/validate_openclaw_operations_runbook_pack.sh
	@bash ports/openclaw/tests/e2e/validate_openclaw_port_campaign.sh
	@bash tests/e2e/validate_non_k8s_adaptation_guide.sh
	@echo "validate-compose: PASS"

validate-k8s:
	@echo "=== K8s validation suite ==="
	$(MAKE) k8s-validate
	@bash tests/e2e/validate_k8s_hardening_guide.sh
	@bash tests/e2e/validate_promotion_identity_policy.sh
	@bash tests/e2e/validate_ci_gate_parity.sh
	@bash tests/e2e/validate_local_k8s_runtime_campaign_artifacts.sh
	@bash tests/e2e/validate_production_reality_closure_local_artifacts.sh
	@echo "validate-k8s: PASS"

# Individual compose validation targets (demoted from visible)
.PHONY: compose-production-intent-preflight compose-production-intent-preflight-signature-prereqs
.PHONY: compose-production-intent-validate operations-readiness-validate
.PHONY: managed-cloud-bootstrap-prereqs-validate framework-taxonomy-mappings-validate
.PHONY: app-pack-model-validate app-integration-strategy-docs-validate
.PHONY: gateway-bypass-case26-validate observability-evidence-gate-validate
.PHONY: spike-shamir-validate

compose-production-intent-preflight:
	@bash tests/e2e/validate_spike_shamir_profiles.sh
	@bash scripts/compose-production-intent-preflight.sh

compose-production-intent-preflight-signature-prereqs:
	@bash tests/e2e/validate_compose_signature_prereqs.sh

compose-production-intent-validate:
	@bash tests/e2e/validate_compose_production_intent_supply_chain.sh
	@bash tests/e2e/validate_compose_production_intent_egress.sh

operations-readiness-validate:
	@bash tests/e2e/validate_operational_readiness_pack.sh

managed-cloud-bootstrap-prereqs-validate:
	@bash tests/e2e/validate_managed_cloud_bootstrap_prereqs.sh

framework-taxonomy-mappings-validate:
	@bash tests/e2e/validate_framework_taxonomy_mappings.sh

app-pack-model-validate:
	@bash tests/e2e/validate_app_integration_pack_model.sh

app-integration-strategy-docs-validate:
	@bash tests/e2e/validate_app_integration_strategy_docs.sh

gateway-bypass-case26-validate:
	@bash tests/e2e/validate_gateway_bypass_case26.sh

observability-evidence-gate-validate:
	@bash tests/e2e/validate_observability_evidence_gate.sh

spike-shamir-validate:
	@bash tests/e2e/validate_spike_shamir_profiles.sh

# Individual K8s validation targets (demoted from visible)
.PHONY: strict-runtime-validate strict-overlay-operationalization-validate
.PHONY: promotion-identity-validate ci-gate-parity-validate k8s-overlay-digest-validate
.PHONY: local-k8s-runtime-campaign-artifacts-validate production-reality-closure-local-artifacts-validate

strict-runtime-validate:
	tests/e2e/validate_strict_runtime_wiring.sh

strict-overlay-operationalization-validate:
	tests/e2e/validate_strict_overlay_operationalization.sh

k8s-overlay-digest-validate:
	OVERLAYS="$(OVERLAYS)" bash tests/e2e/admission/verify-overlay-image-digests.sh

promotion-identity-validate:
	tests/e2e/validate_promotion_identity_policy.sh

ci-gate-parity-validate:
	tests/e2e/validate_ci_gate_parity.sh

local-k8s-runtime-campaign-artifacts-validate:
	tests/e2e/validate_local_k8s_runtime_campaign_artifacts.sh

production-reality-closure-local-artifacts-validate:
	tests/e2e/validate_production_reality_closure_local_artifacts.sh

# ---------------------------------------------------------------------------
# 9. Individual demos (demoted from visible)
# ---------------------------------------------------------------------------

.PHONY: precinct-demo precinct-operate-demo compliance-demo repave-demo upgrade-demo
.PHONY: demo-compose-strict-observability demo-extensions

precinct-demo:
	@bash scripts/ensure-stack.sh
	@mkdir -p build/bin
	@go build -o build/bin/precinct ./cli/agw/
	$(call run_demo_test,precinct-demo,tests/e2e/test_agw_cli.sh)

precinct-operate-demo:
	@bash scripts/ensure-stack.sh --resilient
	@mkdir -p build/bin
	@go build -o build/bin/precinct ./cli/agw/
	$(call run_demo_test,precinct-operate-demo,tests/e2e/test_agw_operate.sh)

compliance-demo:
	@bash scripts/ensure-stack.sh --resilient
	@mkdir -p build/bin
	@go build -o build/bin/precinct ./cli/agw/
	$(call run_demo_test,compliance-demo,tests/e2e/test_agw_compliance.sh)

repave-demo: up
	@mkdir -p build/bin
	@go build -o build/bin/precinct ./cli/agw/
	$(call run_demo_test,repave-demo,tests/e2e/test_repave.sh)

upgrade-demo:
	@if ! bash scripts/compose-health-check.sh; then \
		echo "Core services not fully healthy. Running make up..."; \
		$(MAKE) up; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi
	$(call run_demo_test,upgrade-demo,tests/e2e/test_upgrade.sh)

demo-compose-strict-observability:
	@DEMO_STRICT_OBSERVABILITY=1 bash examples/run.sh compose --no-teardown

demo-extensions:
	@docker build -f examples/content-scanner/Dockerfile -t poc-content-scanner:latest examples/content-scanner/
	@bash tests/e2e/scenario_h_extensions.sh

# ---------------------------------------------------------------------------
# 10. CI components (conformance, benchmark, build-images, build-tools)
# ---------------------------------------------------------------------------

.PHONY: conformance benchmark build-tools build-images build build-cli install

conformance:
	go run ./tests/conformance/cmd/harness --output $(CONFORMANCE_REPORT)

benchmark:
	@echo "Phase 1: Go Benchmarks (13-middleware chain)"
	go test -bench=BenchmarkFullMiddlewareChain -benchmem -run=^$$ ./internal/gateway/middleware/ -count=3
	@echo ""
	go test -bench=BenchmarkMinimalChain -benchmem -run=^$$ ./internal/gateway/middleware/ -count=3
	@echo ""
	@echo "Phase 2: Latency Percentiles (P50/P95/P99)"
	go test -bench=BenchmarkLatencyPercentiles -benchmem -run=^$$ ./internal/gateway/middleware/ -v
	@echo ""
	@echo "Phase 3: Per-Middleware Breakdown"
	go test -bench=BenchmarkPerMiddlewareLatency -benchmem -run=^$$ ./internal/gateway/middleware/ -v
	@echo ""
	@echo "Phase 4: Full vs Minimal Comparison"
	go test -bench=BenchmarkCompareFullVsMinimal -benchmem -run=^$$ ./internal/gateway/middleware/ -v
	@echo ""
	@echo "Phase 5: Benchmark Report"
	BENCHMARK_REPORT=1 go test -run=TestPrintBenchmarkReport -v ./internal/gateway/middleware/
	@echo ""
	@echo "Phase 6: Load Test (Docker Compose)"
	@if $(DC) ps --format '{{.State}}' 2>/dev/null | grep -q 'running'; then \
		if command -v hey >/dev/null 2>&1; then \
			bash tests/benchmark/load_test.sh; \
		else \
			echo "WARNING: 'hey' not installed, skipping load test"; \
		fi; \
	else \
		echo "Docker Compose stack not running, skipping load test"; \
	fi

build-tools:
	@mkdir -p build/bin
	go build -o build/bin/precinct ./cli/agw/
	go build -o build/bin/openclaw-ws-smoke ./ports/openclaw/cmd/openclaw-ws-smoke

.PHONY: openclaw-demo
openclaw-demo: ## Run OpenClaw E2E against live Compose stack (brings stack up if needed)
	@echo "=== OpenClaw Port Demo (E2E against live stack) ==="
	@bash scripts/ensure-stack.sh --resilient
	@echo "--- Unit tests (mock-backed) ---"
	go test ./ports/openclaw/... -count=1
	@echo "--- E2E: walking skeleton against live gateway ---"
	@bash ports/openclaw/tests/e2e/scenario_j_openclaw_walking_skeleton.sh
	@echo "--- E2E: port validation campaign ---"
	@bash ports/openclaw/tests/e2e/validate_openclaw_port_campaign.sh
	@echo "--- E2E: messaging send/receive ---"
	@bash ports/openclaw/tests/e2e/scenario_k_messaging_send_receive.sh
	@echo "--- E2E: exfiltration via messaging ---"
	@bash ports/openclaw/tests/e2e/scenario_l_messaging_exfiltration.sh
	@echo "=== OpenClaw Port Demo PASSED ==="

.PHONY: openclaw-drill
openclaw-drill:
	@bash ports/openclaw/scripts/run_openclaw_incident_rollback_drill.sh

.PHONY: test-openclaw
test-openclaw:
	go test ./ports/openclaw/... -count=1

build-images:
	@echo "Building container images..."
	docker build -f deploy/compose/Dockerfile.gateway -t $(GATEWAY_IMAGE):$(IMAGE_TAG) .
	docker tag $(GATEWAY_IMAGE):$(IMAGE_TAG) $(GATEWAY_IMAGE):dev
	docker build -f deploy/compose/Dockerfile.s3-mcp-server -t $(S3_MCP_IMAGE):$(IMAGE_TAG) .
	docker tag $(S3_MCP_IMAGE):$(IMAGE_TAG) $(S3_MCP_IMAGE):dev
	@echo "Built: $(GATEWAY_IMAGE):$(IMAGE_TAG), $(S3_MCP_IMAGE):$(IMAGE_TAG)"

build: build-cli ## Build service binaries and CLI
	@echo "Building PRECINCT Gateway..."
	$(DC) build mcp-security-gateway

build-cli: ## Build CLI binary (delegates to cli/Makefile)
	$(MAKE) -C cli build

install: ## Install CLI binary (delegates to cli/Makefile)
	$(MAKE) -C cli install

# ---------------------------------------------------------------------------
# 11. Security scans
# ---------------------------------------------------------------------------

.PHONY: security-scan security-scan-strict security-scan-validate manifest-policy-check control-matrix-check

security-scan:
	SECURITY_SCAN_STRICT=0 scripts/security/collect-security-scan-artifacts.sh

security-scan-strict:
	SECURITY_SCAN_STRICT=1 scripts/security/collect-security-scan-artifacts.sh

security-scan-validate:
	tests/e2e/validate_security_scan_artifacts.sh

manifest-policy-check:
	go run ./cmd/manifest-policy-check

control-matrix-check:
	go run ./cmd/control-matrix-check

# ---------------------------------------------------------------------------
# 12. Compliance tools
# ---------------------------------------------------------------------------

.PHONY: compliance-report compliance-evidence test-compliance gdpr-delete gdpr-ropa

$(COMPLIANCE_VENV): tools/compliance/requirements.txt
	python3 -m venv $(COMPLIANCE_VENV)
	$(COMPLIANCE_PYTHON) -m pip install --quiet -r tools/compliance/requirements.txt

compliance-report: test-compliance
	@if $(DC) ps --format '{{.State}}' 2>/dev/null | grep -q 'running'; then \
		echo "Running E2E suite for fresh audit logs..."; \
		bash tests/e2e/run_all.sh 2>&1 || true; \
		$(DC) logs --no-log-prefix mcp-security-gateway 2>/dev/null | grep '{' > $(AUDIT_LOG) || true; \
	else \
		echo "Docker stack not running, using existing audit log at $(AUDIT_LOG)"; \
	fi
	$(COMPLIANCE_PYTHON) tools/compliance/generate.py --audit-log $(AUDIT_LOG) --project-root .

compliance-evidence:
	@if [ -z "$(FRAMEWORK)" ]; then \
		echo "Usage: make compliance-evidence FRAMEWORK=soc2 [SIGN=1] [COSIGN_KEY=.cosign/cosign.key]"; \
		exit 1; \
	fi
	@args=""; \
	if [ "$(SIGN)" = "1" ]; then args="$$args --sign"; fi; \
	if [ -n "$(COSIGN_KEY)" ]; then args="$$args --cosign-key $(COSIGN_KEY)"; fi; \
	go run ./cli/agw compliance collect --framework "$(FRAMEWORK)" $$args

test-compliance: $(COMPLIANCE_VENV)
	cd tools/compliance && $(CURDIR)/$(COMPLIANCE_PYTHON) -m pytest test_generate.py -v

gdpr-ropa:
	@cat docs/compliance/gdpr-article-30-ropa.md

gdpr-delete:
	@if [ -z "$(SPIFFE_ID)" ]; then \
		echo "Usage: make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example"; \
		exit 1; \
	fi
	go run ./cli/agw gdpr delete "$(SPIFFE_ID)" --confirm

# ---------------------------------------------------------------------------
# 13. Internal helpers and operational targets
# ---------------------------------------------------------------------------

.PHONY: setup register-spire k8s-register-spire k8s-prereqs k8s-registry
.PHONY: k8s-runtime-campaign operations-backup-restore-drill
.PHONY: readiness-state-validate validate-setup-time
.PHONY: test-spike-seeder-groq test-gateway-spike-key test-guard-model-e2e

GATEKEEPER_VERSION ?= v3.16.0
GATEKEEPER_URL := https://raw.githubusercontent.com/open-policy-agent/gatekeeper/$(GATEKEEPER_VERSION)/deploy/gatekeeper.yaml

k8s-registry:
	@if ! docker ps --filter name=registry --format '{{.Names}}' 2>/dev/null | grep -q '^registry$$'; then \
		echo "Starting local registry (registry:2 on port 5050)..."; \
		docker rm -f registry 2>/dev/null || true; \
		docker run -d --name registry --restart always -p 5050:5000 registry:2; \
	else \
		echo "Local registry already running"; \
	fi
	@if ! docker network inspect kind --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -q 'registry'; then \
		echo "Connecting registry to kind network..."; \
		docker network connect kind registry 2>/dev/null || true; \
	fi
	@if ! docker exec desktop-control-plane test -f "/etc/containerd/certs.d/registry:5000/hosts.toml" 2>/dev/null; then \
		echo "Configuring K8s containerd for local registry (HTTP)..."; \
		docker exec desktop-control-plane mkdir -p "/etc/containerd/certs.d/registry:5000"; \
		docker exec desktop-control-plane sh -c 'printf "server = \"http://registry:5000\"\n\n[host.\"http://registry:5000\"]\ncapabilities = [\"pull\", \"resolve\", \"push\"]\nskip_verify = true\n" > /etc/containerd/certs.d/registry:5000/hosts.toml'; \
	fi

k8s-prereqs:
	@echo "Installing CRD prerequisites..."
	@if ! kubectl -n gatekeeper-system get deployment gatekeeper-controller-manager -o jsonpath='{.status.availableReplicas}' 2>/dev/null | grep -q '[0-9]'; then \
		echo "  Cleaning up orphaned Gatekeeper webhooks (if any)..."; \
		kubectl delete validatingwebhookconfigurations gatekeeper-validating-webhook-configuration --ignore-not-found 2>/dev/null || true; \
		kubectl delete mutatingwebhookconfigurations gatekeeper-mutating-webhook-configuration --ignore-not-found 2>/dev/null || true; \
		echo "  Installing OPA Gatekeeper $(GATEKEEPER_VERSION)..."; \
		kubectl apply -f $(GATEKEEPER_URL); \
		echo "  Waiting for Gatekeeper deployments..."; \
		kubectl -n gatekeeper-system rollout status deployment/gatekeeper-controller-manager --timeout=120s; \
		kubectl -n gatekeeper-system rollout status deployment/gatekeeper-audit --timeout=120s; \
	else \
		echo "  OPA Gatekeeper already running"; \
	fi
	@if ! kubectl get crd clusterimagepolicies.policy.sigstore.dev >/dev/null 2>&1; then \
		echo "  Installing sigstore policy-controller CRDs..."; \
		kubectl apply -f infra/eks/crds/policy-controller-crds.yaml; \
	else \
		echo "  sigstore policy-controller CRDs already installed"; \
	fi

setup:
	@bash scripts/setup.sh

COMPOSE_SPIRE_EXEC := $(DC) exec -T spire-server /opt/spire/bin/spire-server
COMPOSE_SPIRE_SOCK := /tmp/spire-server/private/api.sock
COMPOSE_TRUST_DOMAIN := poc.local
COMPOSE_PARENT_ID := spiffe://$(COMPOSE_TRUST_DOMAIN)/spire/agent/join_token

register-spire:
	@echo "Registering SPIRE workload entries..."
	@echo "  Detecting SPIRE agent identity..."
	@AGENT_LIST=$$($(COMPOSE_SPIRE_EXEC) agent list -socketPath $(COMPOSE_SPIRE_SOCK) 2>/dev/null || true); \
	PARENT_ID=""; \
	if [ -n "$$AGENT_LIST" ]; then \
		NOW_UTC=$$(date -u '+%Y-%m-%d %H:%M:%S'); \
		PARENT_ID=$$(printf '%s\n' "$$AGENT_LIST" | awk -v now="$$NOW_UTC" '\
			/SPIFFE ID[[:space:]]*:/ { id=$$NF } \
			/Expiration time[[:space:]]*:/ { \
				expiry=$$4" "$$5; \
				if (expiry >= now) { \
					if (best_expiry == "" || expiry > best_expiry) { \
						best_expiry=expiry; \
						best_id=id; \
					} \
				} \
			} \
			END { if (best_id != "") print best_id }'); \
		if [ -z "$$PARENT_ID" ]; then \
			PARENT_ID=$$(printf '%s\n' "$$AGENT_LIST" | grep 'SPIFFE ID' | tail -1 | awk '{print $$NF}'); \
		fi; \
	fi; \
	if [ -z "$$PARENT_ID" ]; then \
		echo "  No agent entry yet, using default parent: $(COMPOSE_PARENT_ID)"; \
		PARENT_ID="$(COMPOSE_PARENT_ID)"; \
	fi; \
	echo "  Parent ID: $$PARENT_ID"; \
	echo "  Registering gateway workload..."; \
	$(COMPOSE_SPIRE_EXEC) entry create -socketPath $(COMPOSE_SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://$(COMPOSE_TRUST_DOMAIN)/gateways/mcp-security-gateway/dev \
		-selector docker:label:spiffe-id:mcp-security-gateway \
		-selector docker:label:component:gateway 2>/dev/null || true; \
	echo "  Registering DSPy researcher agent..."; \
	$(COMPOSE_SPIRE_EXEC) entry create -socketPath $(COMPOSE_SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://$(COMPOSE_TRUST_DOMAIN)/agents/mcp-client/dspy-researcher/dev \
		-selector docker:label:spiffe-id:dspy-researcher 2>/dev/null || true; \
	echo "  Registering PydanticAI researcher agent..."; \
	$(COMPOSE_SPIRE_EXEC) entry create -socketPath $(COMPOSE_SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://$(COMPOSE_TRUST_DOMAIN)/agents/mcp-client/pydantic-researcher/dev \
		-selector docker:label:spiffe-id:pydantic-researcher 2>/dev/null || true; \
	echo "  Registering spike-nexus..."; \
	$(COMPOSE_SPIRE_EXEC) entry create -socketPath $(COMPOSE_SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://$(COMPOSE_TRUST_DOMAIN)/spike/nexus \
		-selector docker:label:spiffe-id:spike-nexus 2>/dev/null || true; \
	echo "  Registering KeyDB..."; \
	$(COMPOSE_SPIRE_EXEC) entry create -socketPath $(COMPOSE_SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://$(COMPOSE_TRUST_DOMAIN)/keydb \
		-selector docker:label:spiffe-id:keydb 2>/dev/null || true; \
	echo "  Current entry count:"; \
	ENTRY_COUNT=$$($(COMPOSE_SPIRE_EXEC) entry show -socketPath $(COMPOSE_SPIRE_SOCK) | grep -c '^Entry ID' || true); \
	echo "    $$ENTRY_COUNT entries"

SPIRE_SOCK := /tmp/spire-server/private/api.sock
SPIRE_EXEC := kubectl -n spire-system exec spire-server-0 -- /opt/spire/bin/spire-server

k8s-register-spire:
	@if ! kubectl -n spire-system get pod spire-server-0 -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Running; then \
		echo "ERROR: spire-server-0 not running. Deploy first: make k8s-up"; \
		exit 1; \
	fi
	@echo "  Detecting SPIRE agent identity..."
	@PARENT_ID=""; \
	i=0; \
	while [ $$i -lt 60 ]; do \
		PARENT_ID=$$($(SPIRE_EXEC) agent list -socketPath $(SPIRE_SOCK) 2>/dev/null | \
			grep 'SPIFFE ID' | head -1 | awk '{print $$NF}'); \
		if [ -n "$$PARENT_ID" ]; then break; fi; \
		i=$$(( $$i + 1 )); \
		echo "  Waiting for SPIRE agent attestation... ($$i/60)"; \
		sleep 2; \
	done; \
	if [ -z "$$PARENT_ID" ]; then \
		echo "ERROR: No SPIRE node entry found. Is the agent attested?"; \
		exit 1; \
	fi; \
	echo "  Agent SPIFFE ID: $$PARENT_ID"; \
	echo "  Registering gateway workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/ns/gateway/sa/mcp-security-gateway \
		-selector k8s:ns:gateway -selector k8s:sa:mcp-security-gateway \
		-dns mcp-security-gateway \
		-dns mcp-security-gateway.gateway.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering mcp-tool workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/ns/tools/sa/mcp-tool \
		-selector k8s:ns:tools -selector k8s:sa:mcp-tool 2>/dev/null || true; \
	echo "  Registering spike-nexus workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/spike/nexus \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-nexus \
		-dns spike-nexus \
		-dns spike-nexus.spike-system.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering spike-keeper workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/spike/keeper/1 \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-keeper \
		-dns spike-keeper-1 \
		-dns spike-keeper-1.spike-system.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering spike-bootstrap workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/spike/bootstrap \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-bootstrap 2>/dev/null || true; \
	echo "  Registering spike-seeder workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/spike/pilot/role/superuser/seeder \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-seeder 2>/dev/null || true; \
	echo "  Registering opensearch workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/ns/observability/sa/opensearch \
		-selector k8s:ns:observability -selector k8s:sa:opensearch \
		-dns opensearch \
		-dns opensearch.observability.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering opensearch-dashboards workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/ns/observability/sa/opensearch-dashboards \
		-selector k8s:ns:observability -selector k8s:sa:opensearch-dashboards \
		-dns opensearch-dashboards \
		-dns opensearch-dashboards.observability.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering opensearch-audit-forwarder workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://precinct.poc/ns/observability/sa/opensearch-audit-forwarder \
		-selector k8s:ns:observability -selector k8s:sa:opensearch-audit-forwarder 2>/dev/null || true; \
	echo "  Current entries:"; \
	$(SPIRE_EXEC) entry show -socketPath $(SPIRE_SOCK)

k8s-runtime-campaign:
	python3 tests/e2e/k8s_runtime_validation_campaign.py \
		--output build/validation/k8s-runtime-validation-report.v2.4.json

operations-backup-restore-drill:
	@bash scripts/operations/run_backup_restore_drill.sh

readiness-state-validate: ## Validate readiness docs/state snapshot against live nd status
	tests/e2e/validate_readiness_state_integrity.sh "$(SNAPSHOT)"

validate-setup-time:
	@if [ -z "$(MODE)" ]; then \
		echo "Usage: make validate-setup-time MODE=compose|k8s"; \
		exit 1; \
	fi
	@bash tests/e2e/validate_setup_time.sh $(MODE)

test-spike-seeder-groq:
	@bash tests/integration/test_spike_seeder_groq.sh

test-gateway-spike-key:
	@bash tests/integration/test_gateway_spike_key.sh

test-guard-model-e2e:
	@bash tests/e2e/test_guard_model_e2e.sh

# ---------------------------------------------------------------------------
# 14. Attestation re-signing
# ---------------------------------------------------------------------------

.PHONY: attestation-resign

attestation-resign: ## Re-sign attestation artifacts (generates keypair if missing)
	@echo "=== Attestation Re-signing ==="
	go run ./cmd/attestation-sign
	@echo ""
	@echo "attestation-resign: DONE"

# ---------------------------------------------------------------------------
# 15. Aliases (backwards compatibility)
# ---------------------------------------------------------------------------

k8s-local-up: k8s-up
k8s-local-down: k8s-down
k8s-local-opensearch-up: k8s-opensearch-up
k8s-local-opensearch-down: k8s-opensearch-down
clean-logs:
	@if [ -d build/logs ]; then rm -rf build/logs/*; fi
