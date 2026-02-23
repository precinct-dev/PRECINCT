# Container image config
REGISTRY ?= ghcr.io
IMAGE_PREFIX ?= $(REGISTRY)/$(shell git config --get remote.origin.url 2>/dev/null | sed 's|.*github.com[:/]\(.*\)\.git|\1|' | tr '[:upper:]' '[:lower:]')/agentic-ref-arch
GATEWAY_IMAGE ?= $(IMAGE_PREFIX)/mcp-security-gateway
S3_MCP_IMAGE ?= $(IMAGE_PREFIX)/s3-mcp-server
IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Local registry (CNCF Distribution) for Docker Desktop K8s
LOCAL_REGISTRY ?= localhost:5050
K8S_REGISTRY ?= registry:5000

# Compliance tooling
AUDIT_LOG ?= /tmp/audit.jsonl
COMPLIANCE_VENV := tools/compliance/.venv
COMPLIANCE_PYTHON := $(COMPLIANCE_VENV)/bin/python3
CONFORMANCE_REPORT ?= build/conformance/conformance-report.json

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# run_demo_test -- Run a test script and report PASS/FAIL
# Usage: $(call run_demo_test,<label>,<script>)
define run_demo_test
	@if bash $(2); then echo "$(1): PASS"; else echo "$(1): FAIL"; exit 1; fi
endef

# ---------------------------------------------------------------------------
# Default
# ---------------------------------------------------------------------------

.PHONY: help
help: ## Show available targets
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

.PHONY: compose-verify compose-production-intent-preflight compose-production-intent-preflight-signature-prereqs compose-production-intent-validate compose-bootstrap-verify
.PHONY: operations-backup-restore-drill operations-readiness-validate managed-cloud-bootstrap-prereqs-validate
.PHONY: framework-taxonomy-mappings-validate app-pack-model-validate app-integration-strategy-docs-validate
.PHONY: gateway-bypass-case26-validate observability-evidence-gate-validate
.PHONY: up down repave upgrade-check upgrade upgrade-all

compose-verify: ## Verify Compose third-party images are digest-pinned (no :latest)
	@bash scripts/compose-verify.sh

compose-production-intent-preflight: ## Validate compose production-intent image lock + provenance policy wiring
	@bash scripts/compose-production-intent-preflight.sh

compose-production-intent-preflight-signature-prereqs: ## Validate fail-closed compose live-signature prerequisite behavior
	@bash tests/e2e/validate_compose_signature_prereqs.sh

compose-production-intent-validate: ## Validate compose production-intent gate including deterministic negative-path failure
	@bash tests/e2e/validate_compose_production_intent_supply_chain.sh
	@bash tests/e2e/validate_compose_production_intent_egress.sh

operations-backup-restore-drill: ## Execute operational backup/restore drill and write auditable artifacts
	@bash scripts/operations/run_backup_restore_drill.sh

operations-readiness-validate: ## Validate operational readiness pack (runbooks + drill artifacts + SLO ownership)
	@bash tests/e2e/validate_operational_readiness_pack.sh

managed-cloud-bootstrap-prereqs-validate: ## Validate managed-cloud bootstrap prerequisite contract and deterministic preflight behavior
	@bash tests/e2e/validate_managed_cloud_bootstrap_prereqs.sh

framework-taxonomy-mappings-validate: ## Validate MITRE ATLAS + OWASP taxonomy mapping coverage for framework_refs signal keys
	@bash tests/e2e/validate_framework_taxonomy_mappings.sh

app-pack-model-validate: ## Validate app integration pack model docs and reference pack manifest
	@bash tests/e2e/validate_app_integration_pack_model.sh

app-integration-strategy-docs-validate: ## Validate no-upstream-mod integration strategy docs and cross-links
	@bash tests/e2e/validate_app_integration_strategy_docs.sh

gateway-bypass-case26-validate: ## Validate SDK case-26 gateway-bypass timeout conformance across compose+k8s logs
	@bash tests/e2e/validate_gateway_bypass_case26.sh

observability-evidence-gate-validate: ## Validate strict/non-strict observability evidence gate behavior
	@bash tests/e2e/validate_observability_evidence_gate.sh

compose-bootstrap-verify: ## Verify one-shot bootstrap containers completed successfully
	@bash scripts/compose-bootstrap-verify.sh

up: compose-verify ## Start Docker Compose stack (waits for all services healthy)
	@if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then \
		echo "ERROR: phoenix-observability-network not found."; \
		echo "Start the Phoenix stack first: make phoenix-up"; \
		exit 1; \
	fi
	@echo "Building and starting services (waiting for all health checks)..."
	@if docker compose up -d --build --wait --wait-timeout 180; then \
		echo "All services healthy."; \
	else \
		echo "WARN: docker compose --wait timed out. Checking core service readiness..."; \
		if ! bash scripts/compose-health-check.sh --verbose; then \
			echo "Attempting gateway-only recovery after compose dependency timeout..."; \
			docker compose up -d --no-deps mcp-security-gateway >/dev/null 2>&1 || true; \
			sleep 5; \
			if ! bash scripts/compose-health-check.sh --verbose; then \
				echo "ERROR: Compose startup failed and required services are not ready."; \
				docker compose ps; \
				exit 1; \
			fi; \
		fi; \
		echo "Core services are ready despite compose wait timeout; continuing."; \
		fi
		@$(MAKE) compose-bootstrap-verify
		@echo "Running register-spire for any additional entries..."
		$(MAKE) register-spire

down: ## Stop Docker Compose stack
	docker compose down

repave: ## Repave containers. Default: full-stack in dependency order. Optional: single component (ex: make repave COMPONENT=keydb)
	@if [ -n "$(COMPONENT)" ]; then \
		bash scripts/repave.sh "$(COMPONENT)"; \
	else \
		bash scripts/repave.sh --all; \
	fi

upgrade-check: ## Show current vs latest versions (containers, Go modules, Python deps) in table + JSON
	@bash scripts/upgrade-check.sh --format table
	@echo ""
	@bash scripts/upgrade-check.sh --format json

upgrade: ## Upgrade a single component (ex: make upgrade COMPONENT=keydb VERIFY=1)
	@if [ -z "$(COMPONENT)" ]; then \
		echo "ERROR: COMPONENT is required (ex: make upgrade COMPONENT=keydb)"; \
		exit 1; \
	fi
	@args="--component $(COMPONENT)"; \
	if [ "$(VERIFY)" = "1" ]; then args="$$args --verify"; fi; \
	bash scripts/upgrade.sh $$args

upgrade-all: ## Upgrade all non-pinned components (ex: make upgrade-all VERIFY=1)
	@args="--all"; \
	if [ "$(VERIFY)" = "1" ]; then args="$$args --verify"; fi; \
	bash scripts/upgrade.sh $$args

# ---------------------------------------------------------------------------
# Stakeholder demos
# ---------------------------------------------------------------------------

.PHONY: upgrade-demo repave-demo agw-demo agw-operate-demo compliance-demo

upgrade-demo: ## Stakeholder demo: upgrade check + upgrade + simulated test failure rollback
	@if ! bash scripts/compose-health-check.sh; then \
		echo "Core services not fully healthy. Running make up..."; \
		$(MAKE) up; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi
	$(call run_demo_test,upgrade-demo,tests/e2e/test_upgrade.sh)

repave-demo: up ## Epic 5 demo: single repave + full repave + status + demo-compose validation
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	$(call run_demo_test,repave-demo,tests/e2e/test_repave.sh)

agw-demo: ## Stakeholder demo: validate agw CLI against live Docker Compose stack
	@bash scripts/ensure-stack.sh
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	$(call run_demo_test,agw-demo,tests/e2e/test_agw_cli.sh)

agw-operate-demo: ## Epic 2 operate demo: ensure stack, build agw, run E2E operate script
	@bash scripts/ensure-stack.sh --resilient
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	$(call run_demo_test,agw-operate-demo,tests/e2e/test_agw_operate.sh)

compliance-demo: ## Epic 3 compliance demo: evidence collect + report + GDPR operations
	@bash scripts/ensure-stack.sh --resilient
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	$(call run_demo_test,compliance-demo,tests/e2e/test_agw_compliance.sh)

# ---------------------------------------------------------------------------
# Phoenix Observability (standalone, persistent across demo runs)
# ---------------------------------------------------------------------------

.PHONY: phoenix-up phoenix-down phoenix-reset

phoenix-up: ## Start standalone Phoenix + OTel collector (persistent traces)
	docker compose -f docker-compose.phoenix.yml up -d --build --wait --wait-timeout 60
	@echo "Phoenix UI: http://localhost:6006"

phoenix-down: ## Stop Phoenix stack (preserves trace data)
	docker compose -f docker-compose.phoenix.yml down

phoenix-reset: ## Stop Phoenix stack and destroy trace data
	docker compose -f docker-compose.phoenix.yml down -v

# ---------------------------------------------------------------------------
# Demos (E2E)
# ---------------------------------------------------------------------------

.PHONY: demo demo-compose demo-compose-strict-observability demo-k8s demo-extensions

demo: ## Run E2E demo (Docker Compose + K8s)
	@bash demo/run.sh compose
	@bash demo/run.sh k8s

demo-compose: ## Run E2E demo (Docker Compose)
	@bash demo/run.sh compose

demo-compose-strict-observability: ## Run E2E demo (Docker Compose) with strict observability evidence enforcement
	@DEMO_STRICT_OBSERVABILITY=1 bash demo/run.sh compose

demo-k8s: ## Run E2E demo (K8s)
	@bash demo/run.sh k8s

demo-extensions: ## Run E2E demo for gateway extension slots (assumes Compose stack is running)
	@docker build -f demo/content-scanner/Dockerfile -t poc-content-scanner:latest demo/content-scanner/
	@bash tests/e2e/scenario_h_extensions.sh

# ---------------------------------------------------------------------------
# Kubernetes (Docker Desktop K8s + local registry)
# ---------------------------------------------------------------------------

.PHONY: k8s-up k8s-down k8s-validate k8s-runtime-campaign local-k8s-runtime-campaign-artifacts-validate production-reality-closure-local-artifacts-validate
.PHONY: strict-runtime-validate strict-overlay-operationalization-validate promotion-identity-validate ci-gate-parity-validate

k8s-up: ## Deploy to local K8s (Docker Desktop)
	@if ! kubectl cluster-info 2>/dev/null | grep -q 'Kubernetes control plane'; then \
		echo "ERROR: No Kubernetes cluster. Enable in Docker Desktop: Settings -> Kubernetes"; \
		exit 1; \
	fi
	$(MAKE) k8s-registry
	@echo "Building and pushing local images..."
	docker build -f docker/Dockerfile.gateway -t mcp-security-gateway:latest .
	docker build -f demo/mock-mcp-server/Dockerfile -t poc-mock-mcp-server:latest demo/mock-mcp-server/
	docker build -f docker/Dockerfile.spire-agent -t spire-agent-wrapper:latest .
	docker tag mcp-security-gateway:latest $(LOCAL_REGISTRY)/mcp-security-gateway:latest
	docker push $(LOCAL_REGISTRY)/mcp-security-gateway:latest
	docker tag poc-mock-mcp-server:latest $(LOCAL_REGISTRY)/poc-mock-mcp-server:latest
	docker push $(LOCAL_REGISTRY)/poc-mock-mcp-server:latest
	docker tag spire-agent-wrapper:latest $(LOCAL_REGISTRY)/spire-agent-wrapper:latest
	docker push $(LOCAL_REGISTRY)/spire-agent-wrapper:latest
	docker build -f docker/Dockerfile.spike-keeper -t spike-keeper:latest .
	docker tag spike-keeper:latest $(LOCAL_REGISTRY)/spike-keeper:latest
	docker push $(LOCAL_REGISTRY)/spike-keeper:latest
	docker build -f demo/content-scanner/Dockerfile -t poc-content-scanner:latest demo/content-scanner/
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
	-kubectl -n spike-system apply -f infra/eks/spike/bootstrap-job.yaml >/dev/null 2>&1 || true
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

k8s-validate: ## Validate K8s overlays and Phase 3 gateway wiring (offline-first)
	@set -e; \
	overlays="local dev staging prod"; \
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
	echo "Validating network policy hardening wiring..."; \
	tests/e2e/network-policy/verify-network-policy-manifest-wiring.sh; \
	echo "Validating strict runtime wiring (K8s + Compose)..."; \
	tests/e2e/validate_strict_runtime_wiring.sh; \
	echo "Validating strict overlay operationalization (no placeholders/literal runtime secrets)..."; \
	tests/e2e/validate_strict_overlay_operationalization.sh; \
	echo "k8s-validate: PASS"

strict-runtime-validate: ## Validate strict runtime wiring for K8s overlays and Compose override
	tests/e2e/validate_strict_runtime_wiring.sh

strict-overlay-operationalization-validate: ## Validate staging/prod overlays have no placeholder image refs or in-repo runtime secret defaults
	tests/e2e/validate_strict_overlay_operationalization.sh

promotion-identity-validate: ## Validate promote workflow enforces constrained cosign signer identity checks
	tests/e2e/validate_promotion_identity_policy.sh

ci-gate-parity-validate: ## Validate CI workflow enforces strict readiness + demo parity + scheduled K8s policy gate
	tests/e2e/validate_ci_gate_parity.sh

k8s-runtime-campaign: ## Run K8s runtime allow/deny campaign and emit machine-readable report
	python3 tests/e2e/k8s_runtime_validation_campaign.py \
		--output build/validation/k8s-runtime-validation-report.v2.4.json

local-k8s-runtime-campaign-artifacts-validate: ## Validate local K8s runtime campaign summary artifacts
	tests/e2e/validate_local_k8s_runtime_campaign_artifacts.sh

production-reality-closure-local-artifacts-validate: ## Validate local production-reality closure summary artifacts
	tests/e2e/validate_production_reality_closure_local_artifacts.sh

# ---------------------------------------------------------------------------
# CI / Quality
# ---------------------------------------------------------------------------

.PHONY: test lint clean logs ci conformance benchmark
.PHONY: security-scan security-scan-strict security-scan-validate
.PHONY: readiness-state-validate story-evidence-validate production-readiness-validate

test: ## Run all tests (unit + OPA)
	@echo "Running unit tests..."
	go test ./internal/gateway/... -v -cover
	go test ./internal/gateway/middleware/... -v -cover
	@echo ""
	@echo "Running OPA policy tests..."
	@if command -v opa >/dev/null 2>&1; then \
		opa test config/opa/ -v; \
	else \
		echo "WARNING: opa not installed, skipping OPA tests"; \
	fi

lint: ## Run linters
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		go fmt ./...; \
		go vet ./...; \
	fi

clean: ## Full cleanup (containers, volumes, build artifacts, logs)
	docker compose down -v
	rm -rf build/sbom/ build/bin/
	@if [ -f .beads/daemon.log ]; then \
		: > .beads/daemon.log; \
	fi

logs: ## Tail gateway logs
	docker compose logs -f mcp-security-gateway

ci: lint test conformance build-images ## Full CI pipeline (lint + test + conformance + build)
	@echo "CI pipeline complete"

conformance: ## Run fixture-driven v2.4 conformance harness and emit JSON report
	go run ./tests/conformance/cmd/harness --output $(CONFORMANCE_REPORT)

benchmark: ## Run performance benchmarks
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
	@if docker compose ps --format '{{.State}}' 2>/dev/null | grep -q 'running'; then \
		if command -v hey >/dev/null 2>&1; then \
			bash tests/benchmark/load_test.sh; \
		else \
			echo "WARNING: 'hey' not installed, skipping load test"; \
		fi; \
	else \
		echo "Docker Compose stack not running, skipping load test"; \
	fi

security-scan: ## Run security scans and emit auditable artifacts (non-strict mode)
	SECURITY_SCAN_STRICT=0 scripts/security/collect-security-scan-artifacts.sh

security-scan-strict: ## Run security scans in strict mode (fail if any scanner is skipped/fails)
	SECURITY_SCAN_STRICT=1 scripts/security/collect-security-scan-artifacts.sh

security-scan-validate: ## Validate generated security scan artifact manifest and required files
	tests/e2e/validate_security_scan_artifacts.sh

readiness-state-validate: ## Validate readiness state docs against live bd story state
	tests/e2e/validate_readiness_state_integrity.sh

story-evidence-validate: ## Validate backticked POC evidence paths referenced in a bd story (usage: make story-evidence-validate STORY_ID=<id>)
	@if [ -z "$(STORY_ID)" ]; then \
		echo "ERROR: STORY_ID is required (ex: make story-evidence-validate STORY_ID=RFA-l6h6.6.11)"; \
		exit 1; \
	fi
	tests/e2e/validate_story_evidence_paths.sh "$(STORY_ID)"

production-readiness-validate: security-scan-strict security-scan-validate ## Strict production-readiness security evidence gate
	@echo "production-readiness-validate: PASS"

# ---------------------------------------------------------------------------
# Hidden targets (functional but not shown in make help)
# ---------------------------------------------------------------------------

.PHONY: setup register-spire k8s-register-spire test-integration test-opa test-gateway-spike-key build build-images
.PHONY: compliance-report compliance-evidence test-compliance gdpr-delete gdpr-ropa validate-setup-time repave
.PHONY: k8s-local-up k8s-local-down clean-logs k8s-prereqs k8s-registry

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

COMPOSE_SPIRE_EXEC := docker compose exec -T spire-server /opt/spire/bin/spire-server
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
	echo "  Current entries:"; \
	$(COMPOSE_SPIRE_EXEC) entry show -socketPath $(COMPOSE_SPIRE_SOCK)

test-integration:
	go test -tags=integration ./tests/integration/... -v -timeout 60s

test-spike-seeder-groq: ## Integration test: validate Groq API key seeding into SPIKE (requires running stack)
	@bash tests/integration/test_spike_seeder_groq.sh

test-gateway-spike-key: ## Integration test: validate gateway fetches Groq API key from SPIKE at startup (requires running stack)
	@bash tests/integration/test_gateway_spike_key.sh

test-guard-model-e2e: ## E2E test: validate full Groq API key chain (.env -> seeder -> SPIKE -> gateway -> guard model -> real score)
	@bash tests/e2e/test_guard_model_e2e.sh

test-opa:
	@if command -v opa >/dev/null 2>&1; then \
		opa test config/opa/ -v; \
	else \
		echo "WARNING: opa not installed"; \
	fi

build:
	@echo "Building PRECINCT Gateway..."
	docker compose build mcp-security-gateway

build-images:
	@echo "Building container images..."
	docker build -f docker/Dockerfile.gateway -t $(GATEWAY_IMAGE):$(IMAGE_TAG) .
	docker tag $(GATEWAY_IMAGE):$(IMAGE_TAG) $(GATEWAY_IMAGE):dev
	docker build -f docker/Dockerfile.s3-mcp-server -t $(S3_MCP_IMAGE):$(IMAGE_TAG) .
	docker tag $(S3_MCP_IMAGE):$(IMAGE_TAG) $(S3_MCP_IMAGE):dev
	@echo "Built: $(GATEWAY_IMAGE):$(IMAGE_TAG), $(S3_MCP_IMAGE):$(IMAGE_TAG)"

$(COMPLIANCE_VENV): tools/compliance/requirements.txt
	python3 -m venv $(COMPLIANCE_VENV)
	$(COMPLIANCE_PYTHON) -m pip install --quiet -r tools/compliance/requirements.txt

compliance-report: test-compliance
	@if docker compose ps --format '{{.State}}' 2>/dev/null | grep -q 'running'; then \
		echo "Running E2E suite for fresh audit logs..."; \
		bash tests/e2e/run_all.sh 2>&1 || true; \
		docker compose logs --no-log-prefix mcp-security-gateway 2>/dev/null | grep '{' > $(AUDIT_LOG) || true; \
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
	go run ./cmd/agw compliance collect --framework "$(FRAMEWORK)" $$args

test-compliance: $(COMPLIANCE_VENV)
	cd tools/compliance && $(CURDIR)/$(COMPLIANCE_PYTHON) -m pytest test_generate.py -v

gdpr-ropa:
	@cat docs/compliance/gdpr-article-30-ropa.md

gdpr-delete:
	@if [ -z "$(SPIFFE_ID)" ]; then \
		echo "Usage: make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example"; \
		exit 1; \
	fi
	go run ./cmd/agw gdpr delete "$(SPIFFE_ID)" --confirm

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
		-spiffeID spiffe://agentic-ref-arch.poc/ns/gateway/sa/mcp-security-gateway \
		-selector k8s:ns:gateway -selector k8s:sa:mcp-security-gateway \
		-dns mcp-security-gateway \
		-dns mcp-security-gateway.gateway.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering mcp-tool workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://agentic-ref-arch.poc/ns/tools/sa/mcp-tool \
		-selector k8s:ns:tools -selector k8s:sa:mcp-tool 2>/dev/null || true; \
	echo "  Registering spike-nexus workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://agentic-ref-arch.poc/spike/nexus \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-nexus \
		-dns spike-nexus \
		-dns spike-nexus.spike-system.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering spike-keeper workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://agentic-ref-arch.poc/spike/keeper/1 \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-keeper \
		-dns spike-keeper-1 \
		-dns spike-keeper-1.spike-system.svc.cluster.local 2>/dev/null || true; \
	echo "  Registering spike-bootstrap workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://agentic-ref-arch.poc/spike/bootstrap \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-bootstrap 2>/dev/null || true; \
	echo "  Registering spike-seeder workload..."; \
	$(SPIRE_EXEC) entry create -socketPath $(SPIRE_SOCK) \
		-parentID $$PARENT_ID \
		-spiffeID spiffe://agentic-ref-arch.poc/spike/pilot/role/superuser/seeder \
		-selector k8s:ns:spike-system -selector k8s:sa:spike-seeder 2>/dev/null || true; \
	echo "  Current entries:"; \
	$(SPIRE_EXEC) entry show -socketPath $(SPIRE_SOCK)

validate-setup-time:
	@if [ -z "$(MODE)" ]; then \
		echo "Usage: make validate-setup-time MODE=compose|k8s"; \
		exit 1; \
	fi
	@bash tests/e2e/validate_setup_time.sh $(MODE)

# Aliases (hidden, for backwards compatibility)
k8s-local-up: k8s-up
k8s-local-down: k8s-down
clean-logs:
	@if [ -f .beads/daemon.log ]; then : > .beads/daemon.log; fi
