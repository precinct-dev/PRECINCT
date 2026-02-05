.PHONY: help up down build test test-integration lint demo-walking-skeleton logs clean register-spire

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2}'
	@echo ""

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

demo-walking-skeleton: ## Run the walking skeleton demo (placeholder)
	@echo "==> Running walking skeleton demo..."
	@echo "    [PLACEHOLDER] Walking skeleton demo not yet implemented"
	@echo "    This will demonstrate end-to-end flow from agent -> gateway -> tool"
	@echo ""
	@echo "Demo complete (placeholder)"

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
