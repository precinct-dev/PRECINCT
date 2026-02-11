.PHONY: help up down test lint clean logs demo demo-compose demo-k8s agw-demo agw-operate-demo compliance-demo k8s-up k8s-down ci benchmark security-scan \
       setup register-spire k8s-register-spire test-integration test-opa build build-images \
       compliance-report compliance-evidence test-compliance gdpr-delete gdpr-ropa validate-setup-time repave \
       k8s-local-up k8s-local-down clean-logs k8s-prereqs k8s-registry upgrade-check upgrade upgrade-all \
       upgrade-demo repave-demo phoenix-up phoenix-down phoenix-reset

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

# Default target
help: ## Show available targets
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

up: ## Start Docker Compose stack (waits for all services healthy)
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
		ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
		ok=1; \
		required_running="spire-server spire-agent spike-keeper-1 spike-nexus keydb mock-mcp-server mock-guard-model mcp-security-gateway"; \
		for s in $$required_running; do \
			line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
			state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
			health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
			if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
				ok=0; \
				echo "  Not ready: $$s (state=$$state health=$$health)"; \
			fi; \
		done; \
		if [ "$$ok" -ne 1 ]; then \
			echo "ERROR: Compose startup failed and required services are not ready."; \
			docker compose ps; \
			exit 1; \
		fi; \
		echo "Core services are ready despite compose wait timeout; continuing."; \
	fi
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

upgrade-demo: ## Stakeholder demo: upgrade check + upgrade + simulated test failure rollback
	@required="keydb mcp-security-gateway mock-guard-model mock-mcp-server spire-server spire-agent spike-nexus spike-keeper-1"; \
	ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
	healthy=1; \
	for s in $$required; do \
		line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
		state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
		health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
		if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
			healthy=0; \
			break; \
		fi; \
	done; \
	if [ "$$healthy" -eq 0 ]; then \
		echo "Core services not fully healthy. Running make up..."; \
		$(MAKE) up; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi; \
	if bash tests/e2e/test_upgrade.sh; then \
		echo "upgrade-demo: PASS"; \
	else \
		echo "upgrade-demo: FAIL"; \
		exit 1; \
	fi

repave-demo: up ## Epic 5 demo: single repave + full repave + status + demo-compose validation
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	@if bash tests/e2e/test_repave.sh; then \
		echo "repave-demo: PASS"; \
	else \
		echo "repave-demo: FAIL"; \
		exit 1; \
	fi

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

# ---------------------------------------------------------------------------
# Phoenix Observability (standalone, persistent across demo runs)
# ---------------------------------------------------------------------------

phoenix-up: ## Start standalone Phoenix + OTel collector (persistent traces)
	docker compose -f docker-compose.phoenix.yml up -d --build --wait --wait-timeout 60
	@echo "Phoenix UI: http://localhost:6006"

phoenix-down: ## Stop Phoenix stack (preserves trace data)
	docker compose -f docker-compose.phoenix.yml down

phoenix-reset: ## Stop Phoenix stack and destroy trace data
	docker compose -f docker-compose.phoenix.yml down -v

# ---------------------------------------------------------------------------
# Demos
# ---------------------------------------------------------------------------

demo: ## Run E2E demo (Docker Compose + K8s)
	@bash demo/run.sh compose
	@bash demo/run.sh k8s

demo-compose: ## Run E2E demo (Docker Compose)
	@bash demo/run.sh compose

demo-k8s: ## Run E2E demo (K8s)
	@bash demo/run.sh k8s

agw-demo: ## Stakeholder demo: validate agw CLI against live Docker Compose stack
	@if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then \
		echo "Phoenix network not found. Running make phoenix-up..."; \
		$(MAKE) phoenix-up; \
	fi
	@required="keydb mcp-security-gateway mock-guard-model mock-mcp-server spire-server spire-agent spike-nexus spike-keeper-1"; \
	ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
	healthy=1; \
	for s in $$required; do \
		line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
		state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
		health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
		if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
			healthy=0; \
			break; \
		fi; \
	done; \
	if [ "$$healthy" -eq 0 ]; then \
		echo "Core services not fully healthy. Running make up..."; \
		$(MAKE) up; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	@if bash tests/e2e/test_agw_cli.sh; then \
		echo "agw-demo: PASS"; \
	else \
		echo "agw-demo: FAIL"; \
		exit 1; \
	fi

agw-operate-demo: ## Epic 2 operate demo: ensure stack, build agw, run E2E operate script
	@if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then \
		echo "Phoenix network not found. Running make phoenix-up..."; \
		$(MAKE) phoenix-up; \
	fi
	@required="keydb mcp-security-gateway mock-guard-model mock-mcp-server spire-server spire-agent spike-nexus spike-keeper-1"; \
	ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
	healthy=1; \
	for s in $$required; do \
		line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
		state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
		health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
		if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
			healthy=0; \
			break; \
		fi; \
	done; \
	if [ "$$healthy" -eq 0 ]; then \
		echo "Core services not fully healthy. Running make up..."; \
		if ! $(MAKE) up; then \
			echo "make up returned non-zero. Re-checking service health..."; \
			ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
			recovered=1; \
			for s in $$required; do \
				line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
				state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
				health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
				if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
					recovered=0; \
					break; \
				fi; \
			done; \
			if [ "$$recovered" -eq 0 ]; then \
				echo "ERROR: services are not healthy after make up."; \
				exit 1; \
			fi; \
			echo "Services are healthy despite make up non-zero; continuing."; \
		fi; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	@if bash tests/e2e/test_agw_operate.sh; then \
		echo "agw-operate-demo: PASS"; \
	else \
		echo "agw-operate-demo: FAIL"; \
		exit 1; \
	fi

compliance-demo: ## Epic 3 compliance demo: evidence collect + report + GDPR operations
	@if ! docker network inspect phoenix-observability-network >/dev/null 2>&1; then \
		echo "Phoenix network not found. Running make phoenix-up..."; \
		$(MAKE) phoenix-up; \
	fi
	@required="keydb mcp-security-gateway mock-guard-model mock-mcp-server spire-server spire-agent spike-nexus spike-keeper-1"; \
	ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
	healthy=1; \
	for s in $$required; do \
		line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
		state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
		health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
		if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
			healthy=0; \
			break; \
		fi; \
	done; \
	if [ "$$healthy" -eq 0 ]; then \
		echo "Core services not fully healthy. Running make up..."; \
		if ! $(MAKE) up; then \
			echo "make up returned non-zero. Re-checking service health..."; \
			ps_out="$$(docker compose ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null || true)"; \
			recovered=1; \
			for s in $$required; do \
				line="$$(printf '%s\n' "$$ps_out" | awk -v svc="$$s" '$$1==svc {print}')"; \
				state="$$(printf '%s\n' "$$line" | awk '{print $$2}')"; \
				health="$$(printf '%s\n' "$$line" | awk '{print $$3}')"; \
				if [ -z "$$line" ] || [ "$$state" != "running" ] || { [ -n "$$health" ] && [ "$$health" != "healthy" ]; }; then \
					recovered=0; \
					break; \
				fi; \
			done; \
			if [ "$$recovered" -eq 0 ]; then \
				echo "ERROR: services are not healthy after make up."; \
				exit 1; \
			fi; \
			echo "Services are healthy despite make up non-zero; continuing."; \
		fi; \
	else \
		echo "Core services already running and healthy. Skipping make up."; \
	fi
	@mkdir -p build/bin
	@go build -o build/bin/agw ./cmd/agw/
	@if bash tests/e2e/test_agw_compliance.sh; then \
		echo "compliance-demo: PASS"; \
	else \
		echo "compliance-demo: FAIL"; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Kubernetes (Docker Desktop K8s + local registry)
# ---------------------------------------------------------------------------

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
	$(MAKE) k8s-prereqs
	@echo "Cleaning up completed SPIKE jobs for re-apply..."
	-kubectl -n spike-system delete job spike-bootstrap --ignore-not-found 2>/dev/null
	-kubectl -n spike-system delete job spike-secret-seeder --ignore-not-found 2>/dev/null
	@echo "Applying overlay (pass 1: namespaces, CRDs, services)..."
	-kubectl apply -k infra/eks/overlays/local/ 2>&1 | grep -v 'ensure CRDs are installed first'
	@echo "Waiting for Gatekeeper to process ConstraintTemplates..."
	@sleep 10
	@echo "Applying overlay (pass 2: constraints, policies)..."
	-kubectl apply -k infra/eks/overlays/local/ 2>&1
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
	@echo "Waiting for SPIKE Bootstrap job..."
	-kubectl -n spike-system wait --for=condition=complete job/spike-bootstrap --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIKE Bootstrap not yet complete"
	@echo "Waiting for SPIKE Nexus (SQLite mode)..."
	-kubectl -n spike-system rollout status deployment/spike-nexus --timeout=120s 2>/dev/null || \
		echo "WARNING: SPIKE Nexus not yet ready"
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
	-kubectl delete -k infra/eks/overlays/local/ --ignore-not-found 2>&1 | grep -v -E 'ensure CRDs are installed first|resource mapping not found'
	@echo "Cleaning up Gatekeeper cluster-scoped resources..."
	-kubectl delete validatingwebhookconfigurations gatekeeper-validating-webhook-configuration --ignore-not-found 2>/dev/null
	-kubectl delete mutatingwebhookconfigurations gatekeeper-mutating-webhook-configuration --ignore-not-found 2>/dev/null
	-kubectl -n spire-system delete pvc -l app.kubernetes.io/name=spire-server --ignore-not-found 2>/dev/null

# ---------------------------------------------------------------------------
# CI / Quality
# ---------------------------------------------------------------------------

ci: lint test build-images ## Full CI pipeline (lint + test + build)
	@echo "CI pipeline complete"

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

security-scan: ## Run security scans (gosec, trivy)
	@echo "Scanning Go source with gosec..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "WARNING: gosec not installed, skipping"; \
	fi
	@echo ""
	@echo "Scanning container image with trivy..."
	@if command -v trivy >/dev/null 2>&1; then \
		if docker images -q $(GATEWAY_IMAGE):$(IMAGE_TAG) 2>/dev/null | grep -q .; then \
			trivy image $(GATEWAY_IMAGE):$(IMAGE_TAG); \
		else \
			echo "WARNING: Image $(GATEWAY_IMAGE):$(IMAGE_TAG) not found (run make build-images)"; \
		fi; \
	else \
		echo "WARNING: trivy not installed, skipping"; \
	fi
	@echo ""
	@echo "Scanning filesystem with trivy..."
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --skip-dirs .beads .; \
	else \
		echo "WARNING: trivy not installed, skipping"; \
	fi

# ---------------------------------------------------------------------------
# Hidden targets (functional but not shown in make help)
# ---------------------------------------------------------------------------

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

test-opa:
	@if command -v opa >/dev/null 2>&1; then \
		opa test config/opa/ -v; \
	else \
		echo "WARNING: opa not installed"; \
	fi

build:
	@echo "Building MCP Security Gateway..."
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
