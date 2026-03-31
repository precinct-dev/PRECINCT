.DEFAULT_GOAL := help

BINARY := precinct
BUILD_DIR := ../build/bin

.PHONY: help test build install clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

test: ## Run all CLI tests
	go test ./precinct/... -count=1 -v

build: ## Build the precinct binary
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY) ./precinct/

install: build ## Install precinct to GOPATH/bin
	go install ./precinct/

clean: ## Remove build artifacts
	rm -f $(BUILD_DIR)/$(BINARY)
