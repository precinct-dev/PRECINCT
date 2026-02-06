.PHONY: help setup up down build test test-integration lint demo-walking-skeleton logs clean register-spire tool-register ci build-images sign-images sbom test-opa compliance-report test-compliance gdpr-delete

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""

setup: ## Interactive setup wizard with prerequisite checks and security posture summary (RFA-tj9.2)
	@bash scripts/setup.sh

up: ## Start all services with docker compose and register SPIRE entries
	@echo "Starting services with docker compose..."
	docker compose up -d
	@echo "Waiting for SPIRE server to be healthy..."
	@timeout=60; \
	while ! docker compose exec -T spire-server wget --spider -q http://localhost:8080/ready 2>/dev/null; do \
		timeout=$$((timeout - 1)); \
		if [ $$timeout -le 0 ]; then \
			echo "ERROR: SPIRE server failed to become healthy"; \
			exit 1; \
		fi; \
		sleep 1; \
	done
	@echo "SPIRE server is ready. Registering workload entries..."
	$(MAKE) register-spire

down: ## Stop and remove all services
	@echo "Stopping services..."
	docker compose down

build: ## Build all Go and Python services
	@echo "==> Building Go services..."
	@echo "    Building MCP Security Gateway..."
	docker compose build mcp-security-gateway
	@echo "    [PLACEHOLDER] Tool registry not yet built - see future stories"
	@echo ""
	@echo "==> Building Python services..."
	@echo "    [PLACEHOLDER] Agent services not yet built - see future stories"
	@echo ""
	@echo "Build complete"

test: ## Run unit tests for all services
	@echo "==> Running unit tests..."
	@echo "    Testing MCP Security Gateway..."
	go test ./internal/gateway/... -v -cover
	@echo ""
	@echo "    [PLACEHOLDER] Python tests not yet implemented - see future stories"
	@echo ""
	@echo "Unit tests complete"

test-integration: ## Run integration tests against the compose stack
	@echo "==> Running integration tests..."
	@echo "    Testing MCP Security Gateway integration..."
	@echo "    Note: Requires docker compose stack to be running (make up)"
	go test -tags=integration ./tests/integration/... -v -timeout 60s
	@echo ""
	@echo "Integration tests complete"

lint: ## Run linting for Go and Python code
	@echo "==> Linting Go code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "    golangci-lint not installed, using go fmt and go vet"; \
		go fmt ./...; \
		go vet ./...; \
	fi
	@echo ""
	@echo "==> Linting Python code..."
	@echo "    [PLACEHOLDER] Python linting not yet configured - see future stories"
	@echo ""
	@echo "Linting complete"

demo-walking-skeleton: ## Run the walking skeleton demo (RFA-qq0.13)
	@echo "==> Running walking skeleton demo..."
	@bash scripts/demo-walking-skeleton.sh

logs: ## Tail gateway audit logs
	@echo "==> Tailing MCP Security Gateway logs..."
	@echo "    Note: Gateway is currently a placeholder container (golang:1.23 with sleep infinity)"
	@echo "    Once implemented (story RFA-qq0.3), this will show audit logs"
	@echo ""
	docker compose logs -f mcp-security-gateway

clean: ## Remove built artifacts and Docker volumes
	@echo "==> Cleaning Docker volumes..."
	docker compose down -v
	@echo ""
	@echo "==> Cleaning build artifacts..."
	rm -rf build/
	@echo ""
	@echo "Clean complete"

register-spire: ## Run SPIRE registration script to register workload entries
	@echo "==> Registering SPIRE workload entries..."
	docker compose exec -T spire-server /bin/bash < scripts/register-spire-entries.sh
	@echo ""
	@echo "SPIRE registration complete"

tool-register: ## Register a new MCP tool (RFA-fu1). Usage: make tool-register TOOL_NAME=name TOOL_DESCRIPTION="desc" TOOL_SCHEMA='{"type":"object",...}'
	@if [ -z "$(TOOL_NAME)" ]; then echo "ERROR: TOOL_NAME is required"; echo "Usage: make tool-register TOOL_NAME=name TOOL_DESCRIPTION=\"desc\" TOOL_SCHEMA='{\"type\":\"object\"}'"; exit 1; fi
	@if [ -z "$(TOOL_DESCRIPTION)" ]; then echo "ERROR: TOOL_DESCRIPTION is required"; exit 1; fi
	@test -n '$(TOOL_SCHEMA)' || { echo "ERROR: TOOL_SCHEMA is required"; exit 1; }
	@go run scripts/tool_register/main.go \
		--name "$(TOOL_NAME)" \
		--description "$(TOOL_DESCRIPTION)" \
		--schema '$(TOOL_SCHEMA)' \
		$(if $(RISK_LEVEL),--risk-level "$(RISK_LEVEL)") \
		$(if $(ALLOWED_DESTINATIONS),--allowed-destinations "$(ALLOWED_DESTINATIONS)") \
		$(if $(filter true,$(REQUIRES_STEP_UP)),--requires-step-up)

# ==============================================================================
# CI/CD Targets (RFA-9fv.6)
# ==============================================================================

# Container image names
REGISTRY ?= ghcr.io
IMAGE_PREFIX ?= $(REGISTRY)/$(shell git config --get remote.origin.url 2>/dev/null | sed 's|.*github.com[:/]\(.*\)\.git|\1|' | tr '[:upper:]' '[:lower:]')/agentic-ref-arch
GATEWAY_IMAGE ?= $(IMAGE_PREFIX)/mcp-security-gateway
S3_MCP_IMAGE ?= $(IMAGE_PREFIX)/s3-mcp-server
IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

ci: lint test test-opa build-images ## Run full CI locally (lint, test, OPA tests, build images)
	@echo ""
	@echo "==> CI pipeline complete"

build-images: ## Build all container images
	@echo "==> Building container images..."
	@echo "    Building MCP Security Gateway..."
	docker build -f build/docker/Dockerfile.gateway -t $(GATEWAY_IMAGE):$(IMAGE_TAG) .
	docker tag $(GATEWAY_IMAGE):$(IMAGE_TAG) $(GATEWAY_IMAGE):dev
	@echo ""
	@echo "    Building S3 MCP Server..."
	docker build -f build/docker/Dockerfile.s3-mcp-server -t $(S3_MCP_IMAGE):$(IMAGE_TAG) .
	docker tag $(S3_MCP_IMAGE):$(IMAGE_TAG) $(S3_MCP_IMAGE):dev
	@echo ""
	@echo "Container images built successfully"
	@echo "  $(GATEWAY_IMAGE):$(IMAGE_TAG)"
	@echo "  $(S3_MCP_IMAGE):$(IMAGE_TAG)"

sign-images: ## Sign container images with cosign (keyless OIDC)
	@echo "==> Signing container images with cosign..."
	@if ! command -v cosign >/dev/null 2>&1; then \
		echo "ERROR: cosign not installed. Install from https://docs.sigstore.dev/cosign/system_config/installation/"; \
		exit 1; \
	fi
	@echo "    Signing $(GATEWAY_IMAGE):$(IMAGE_TAG)..."
	cosign sign --yes $(GATEWAY_IMAGE):$(IMAGE_TAG)
	@echo "    Signing $(S3_MCP_IMAGE):$(IMAGE_TAG)..."
	cosign sign --yes $(S3_MCP_IMAGE):$(IMAGE_TAG)
	@echo ""
	@echo "Images signed successfully"

sbom: build-images ## Generate SBOMs for all container images
	@echo "==> Generating SBOMs..."
	@if ! command -v syft >/dev/null 2>&1; then \
		echo "ERROR: syft not installed. Install from https://github.com/anchore/syft"; \
		exit 1; \
	fi
	@mkdir -p build/sbom
	@echo "    Generating SBOM for MCP Security Gateway..."
	syft $(GATEWAY_IMAGE):$(IMAGE_TAG) -o spdx-json > build/sbom/mcp-security-gateway.spdx.json
	@echo "    Generating SBOM for S3 MCP Server..."
	syft $(S3_MCP_IMAGE):$(IMAGE_TAG) -o spdx-json > build/sbom/s3-mcp-server.spdx.json
	@echo ""
	@echo "SBOMs generated in build/sbom/"

test-opa: ## Run OPA policy tests
	@echo "==> Running OPA policy tests..."
	@if command -v opa >/dev/null 2>&1; then \
		opa test config/opa/ -v; \
	else \
		echo "    WARNING: opa not installed. Skipping OPA tests."; \
		echo "    Install from: https://www.openpolicyagent.org/docs/latest/#running-opa"; \
	fi
	@echo ""
	@echo "OPA policy tests complete"

# ==============================================================================
# Compliance Automation (RFA-8jl)
# ==============================================================================

AUDIT_LOG ?= /tmp/audit.jsonl

COMPLIANCE_VENV := tools/compliance/.venv
COMPLIANCE_PYTHON := $(COMPLIANCE_VENV)/bin/python3

$(COMPLIANCE_VENV): tools/compliance/requirements.txt
	@echo "    Setting up compliance venv..."
	python3 -m venv $(COMPLIANCE_VENV)
	$(COMPLIANCE_PYTHON) -m pip install --quiet -r tools/compliance/requirements.txt

compliance-report: $(COMPLIANCE_VENV) ## Generate compliance CSV report (runs E2E suite first if docker stack is up)
	@echo "==> Compliance Report Generation (RFA-8jl)"
	@echo ""
	@if docker compose ps --format '{{.State}}' 2>/dev/null | grep -q 'running'; then \
		echo "    Docker stack detected. Running E2E suite to generate fresh audit logs..."; \
		bash tests/e2e/run_all.sh 2>&1 || true; \
		echo "    Extracting audit logs from gateway container..."; \
		docker compose logs --no-log-prefix mcp-security-gateway 2>/dev/null | grep '{' > $(AUDIT_LOG) || true; \
		echo ""; \
	else \
		echo "    Docker stack not running. Using existing audit log at $(AUDIT_LOG)"; \
		echo "    (Run 'make up' first for fresh audit data)"; \
		echo ""; \
	fi
	@echo "    Generating compliance report..."
	$(COMPLIANCE_PYTHON) tools/compliance/generate.py --audit-log $(AUDIT_LOG) --project-root .
	@echo ""
	@echo "==> Compliance report generation complete"

test-compliance: $(COMPLIANCE_VENV) ## Run compliance tooling tests (unit + integration)
	@echo "==> Running compliance tooling tests..."
	cd tools/compliance && $(CURDIR)/$(COMPLIANCE_PYTHON) -m pytest test_generate.py -v
	@echo ""
	@echo "Compliance tests complete"

# ==============================================================================
# GDPR/CCPA Right-to-Deletion (RFA-hh5.3)
# ==============================================================================

gdpr-delete: ## Delete all session/rate-limit data for a SPIFFE ID. Usage: make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example
	@if [ -z "$(SPIFFE_ID)" ]; then \
		echo "ERROR: SPIFFE_ID is required"; \
		echo "Usage: make gdpr-delete SPIFFE_ID=spiffe://poc.local/agents/example"; \
		exit 1; \
	fi
	go run ./cmd/gdpr-delete/ "$(SPIFFE_ID)"
